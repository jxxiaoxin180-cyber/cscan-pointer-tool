#include <unistd.h>

#include <iostream>
#include <thread>

#include "core.hpp"
#include "httplib.h"
#include "web_assets.hpp"
namespace cs {
int serve(const fs::path& dir, int port) {
  fs::create_directories(dir);
  httplib::Server server;
  server.new_task_queue = []() { return new httplib::ThreadPool(4); };
  server.set_payload_max_length(9 * 1024 * 1024);
  server.set_read_timeout(10);
  server.set_write_timeout(30);
  std::string token = unique_id() + unique_id(), host = "127.0.0.1:" + std::to_string(port),
              localhost = "localhost:" + std::to_string(port);
  std::mutex mutex;
  struct DownloadTicket {
    std::string endpoint, file;
    Clock::time_point expires;
    size_t budget;
  };
  std::mutex download_mutex;
  std::map<std::string, DownloadTicket> download_tickets;
  struct Upload {
    fs::path temporary;
    std::string id, file;
    uint64_t expected = 0, received = 0;
    std::ofstream stream;
    ~Upload() {
      stream.close();
      std::error_code ec;
      fs::remove(temporary, ec);
    }
  };
  std::mutex upload_mutex;
  std::unique_ptr<Upload> upload;
  J state = {{"status", "idle"}, {"events", J::array()}};
  std::shared_ptr<Context> context;
  std::thread worker;
  std::unique_ptr<Fixture> fixture;
  auto json = [](httplib::Response& r, J data, int code = 200) {
    r.status = code;
    r.set_content(data.dump(), "application/json; charset=utf-8");
  };
  server.set_pre_routing_handler([&](const httplib::Request& req, httplib::Response& res) {
    res.set_header("Cache-Control", "no-store");
    res.set_header("X-Content-Type-Options", "nosniff");
    res.set_header("Referrer-Policy", "no-referrer");
    res.set_header(
        "Content-Security-Policy",
        "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; "
        "img-src 'self' data:; connect-src 'self'; frame-ancestors 'none'; base-uri 'none'");
    std::string h = req.get_header_value("Host"), origin = req.get_header_value("Origin");
    if ((h != host && h != localhost) ||
        (!origin.empty() && origin != "http://" + host && origin != "http://" + localhost)) {
      json(res, {{"error", "请求来源不匹配"}}, 403);
      return httplib::Server::HandlerResponse::Handled;
    }
    bool authorized = req.get_header_value("X-CSCAN-Token") == token;
    if (!authorized && req.method == "GET" && req.has_param("ticket")) {
      std::lock_guard<std::mutex> lock(download_mutex);
      auto it = download_tickets.find(req.get_param_value("ticket"));
      if (it != download_tickets.end() && it->second.expires > Clock::now() &&
          req.path == "/api/" + it->second.endpoint &&
          req.get_param_value("file") == it->second.file &&
          req.get_param_value("graph_memory_mb") == std::to_string(it->second.budget)) {
        authorized = true;
        download_tickets.erase(it);
      }
    }
    if (req.path.rfind("/api/", 0) == 0 && !authorized) {
      json(res, {{"error", "页面会话或下载凭据已经失效，请刷新页面后重试"}}, 403);
      return httplib::Server::HandlerResponse::Handled;
    }
    return httplib::Server::HandlerResponse::Unhandled;
  });
  server.set_exception_handler([&](const auto&, auto& res, std::exception_ptr ep) {
    try {
      std::rethrow_exception(ep);
    } catch (const std::exception& e) {
      json(res, {{"error", e.what()}}, 400);
    } catch (...) {
      json(res, {{"error", "内部错误"}}, 500);
    }
  });
  server.Get("/", [&](const auto&, auto& res) {
    std::string html = web_index;
    auto pos = html.find("__SESSION_TOKEN__");
    if (pos != std::string::npos)
      html.replace(pos, 17, token);
    res.set_content(html, "text/html; charset=utf-8");
  });
  server.Get("/app.js", [&](const auto&, auto& res) {
    res.set_content(web_js, "application/javascript; charset=utf-8");
  });
  server.Get("/style.css",
             [&](const auto&, auto& res) { res.set_content(web_css, "text/css; charset=utf-8"); });
  server.Get("/api/status", [&](const auto&, auto& res) {
    json(res, {{"name", "C扫指针工具第一版"},
               {"version", version},
               {"pid", getpid()},
               {"data_dir", dir.string()},
               {"runtime", runtime_info()},
               {"readers", J::array({"normal", "syscall", "pread", "paradise", "paradise35",
                                     "paradise-hook"})}});
  });
  server.Get("/api/processes", [&](const auto&, auto& res) { json(res, processes()); });
  server.Get("/api/process-list", [&](const auto&, auto& res) { json(res, process_catalog()); });
  server.Get("/api/process", [&](const auto& req, auto& res) {
    auto pid = number(req.get_param_value("pid"));
    if (pid == 0 || pid > INT32_MAX)
      throw std::runtime_error("PID 无效");
    auto info = process_probe(pid);
    info["runtime"] = runtime_info();
    json(res, info);
  });
  server.Get("/api/modules", [&](const auto& req, auto& res) {
    auto pid = number(req.get_param_value("pid"));
    if (pid == 0 || pid > INT32_MAX)
      throw std::runtime_error("PID 无效");
    auto t = target(pid);
    json(res, {{"modules", modules(t)},
               {"pid", t.pid},
               {"uid", t.uid},
               {"name", t.name},
               {"bits", t.bits},
               {"identity", t.identity}});
  });
  server.Get("/api/files", [&](const auto&, auto& res) { json(res, list_results(dir)); });
  server.Post("/api/files/delete", [&](const auto& req, auto& res) {
    auto request = J::parse(req.body);
    const auto& names = request.at("files");
    if (!names.is_array() || names.empty() || names.size() > 100)
      throw std::runtime_error("每次请选择 1–100 个文件删除");
    // Serialize against task startup and upload publication. Never remove active inputs.
    std::scoped_lock lock(mutex, upload_mutex);
    if (state["status"] == "running" || upload) {
      json(res, {{"error", "任务或上传正在进行，请结束后再删除文件"}}, 409);
      return;
    }
    std::map<std::string, fs::path> paths;
    for (const auto& value : names) {
      auto name = value.template get<std::string>();
      auto path = safe_file(dir, name);
      if (path.extension() != ".cptr" && path.extension() != ".txt")
        throw std::runtime_error("只能删除结果目录中的 .cptr 或 .txt 文件");
      if (fs::exists(path) && !fs::is_regular_file(path))
        throw std::runtime_error("只能删除普通结果文件，不能删除目录");
      paths.emplace(name, path);
    }
    // Validate the entire request before the first removal; report any I/O partial failure.
    J deleted = J::array(), failed = J::array();
    for (const auto& [name, path] : paths) {
      std::error_code ec;
      bool removed = fs::remove(path, ec);
      if (!removed || ec) {
        failed.push_back({{"file", name}, {"error", ec ? ec.message() : "文件不存在或已被删除"}});
        continue;
      }
      deleted.push_back(name);
      std::lock_guard<std::mutex> ticket_lock(download_mutex);
      for (auto it = download_tickets.begin(); it != download_tickets.end();) {
        if (it->second.file == name)
          it = download_tickets.erase(it);
        else
          ++it;
      }
    }
    json(res, {{"deleted", deleted}, {"failed", failed}});
  });
  server.Get("/api/preview", [&](const auto& req, auto& res) {
    size_t page = req.has_param("page") ? number(req.get_param_value("page")) : 0;
    auto mb =
        req.has_param("graph_memory_mb") ? number(req.get_param_value("graph_memory_mb")) : 128;
    if (mb < 8 || mb > 4096)
      throw std::runtime_error("图预算应为 8–4096 MiB");
    json(res,
         preview(safe_file(dir, req.get_param_value("file")), page, 50, mb * 1024ULL * 1024ULL));
  });
  server.Post("/api/download-ticket", [&](const auto& req, auto& res) {
    auto request = J::parse(req.body);
    auto endpoint = request.at("endpoint").template get<std::string>();
    auto file = request.at("file").template get<std::string>();
    if (endpoint != "download" && endpoint != "export" && endpoint != "text-download")
      throw std::runtime_error("下载类型无效");
    auto path = safe_file(dir, file);
    if (!fs::is_regular_file(path))
      throw std::runtime_error("结果文件不存在");
    auto budget = request.value("graph_memory_mb", size_t(128));
    if (budget < 8 || budget > 4096)
      throw std::runtime_error("图预算应为 8–4096 MiB");
    if (endpoint == "text-download") {
      if (path.extension() != ".txt")
        throw std::runtime_error("文本下载需要 .txt 文件");
    } else {
      StoreReader check(path, budget * 1024ULL * 1024ULL);
    }
    auto ticket = unique_id();
    std::lock_guard<std::mutex> lock(download_mutex);
    for (auto it = download_tickets.begin(); it != download_tickets.end();) {
      if (it->second.expires <= Clock::now())
        it = download_tickets.erase(it);
      else
        ++it;
    }
    if (download_tickets.size() >= 64)
      throw std::runtime_error("待下载任务过多，请稍后再试");
    download_tickets.emplace(
        ticket, DownloadTicket{endpoint, file, Clock::now() + std::chrono::minutes(5), budget});
    json(res, {{"ticket", ticket}});
  });
  server.Post("/api/upload/start", [&](const auto& req, auto& res) {
    auto request = J::parse(req.body);
    auto ext = fs::path(request.at("name").template get<std::string>()).extension();
    if (ext != ".txt" && ext != ".cptr")
      throw std::runtime_error("请选择 .txt 或 .cptr 文件");
    auto size = request.at("bytes").template get<uint64_t>();
    if (size > 64ULL * 1024 * 1024 * 1024)
      throw std::runtime_error("单个上传文件最大 64 GiB");
    std::lock_guard<std::mutex> lock(upload_mutex);
    if (upload)
      throw std::runtime_error("已有文件上传中，请先取消或完成");
    auto next = std::make_unique<Upload>();
    next->id = unique_id();
    next->expected = size;
    next->file = "uploaded-" + next->id + ext.string();
    next->temporary = dir / ("." + next->id + ".upload.part");
    next->stream.open(next->temporary, std::ios::binary);
    if (!next->stream)
      throw std::runtime_error("无法创建上传文件");
    json(res, {{"id", next->id}, {"chunk_bytes", 1024 * 1024}});
    upload = std::move(next);
  });
  server.Post("/api/upload/chunk", [&](const auto& req, auto& res) {
    std::lock_guard<std::mutex> lock(upload_mutex);
    if (!upload || req.get_param_value("id") != upload->id)
      throw std::runtime_error("上传会话无效");
    if (req.body.empty() || req.body.size() > 1024 * 1024 ||
        number(req.get_param_value("offset")) != upload->received ||
        req.body.size() > upload->expected - upload->received)
      throw std::runtime_error("上传块大小或顺序不正确");
    upload->stream.write(req.body.data(), req.body.size());
    upload->stream.flush();
    if (!upload->stream) {
      upload.reset();
      throw std::runtime_error("上传写入失败，请检查磁盘空间");
    }
    upload->received += req.body.size();
    json(res, {{"received", upload->received}});
  });
  server.Post("/api/upload/finish", [&](const auto& req, auto& res) {
    auto request = J::parse(req.body);
    std::lock_guard<std::mutex> lock(upload_mutex);
    if (!upload || request.value("id", "") != upload->id)
      throw std::runtime_error("上传会话无效");
    if (upload->received != upload->expected)
      throw std::runtime_error("文件尚未上传完整");
    upload->stream.close();
    auto file = upload->file;
    if (fs::exists(safe_file(dir, file)))
      throw std::runtime_error("上传目标已存在");
    fs::rename(upload->temporary, safe_file(dir, file));
    upload.reset();
    json(res, {{"file", file}});
  });
  server.Post("/api/upload/cancel", [&](const auto& req, auto& res) {
    auto request = J::parse(req.body);
    std::lock_guard<std::mutex> lock(upload_mutex);
    if (upload && request.value("id", "") == upload->id)
      upload.reset();
    json(res, {{"ok", true}});
  });
  server.Get("/api/download", [&](const auto& req, auto& res) {
    auto path = safe_file(dir, req.get_param_value("file"));
    StoreReader check(path);
    auto stream = std::make_shared<std::ifstream>(path, std::ios::binary);
    uint64_t length = fs::file_size(path);
    res.set_header("Content-Disposition",
                   "attachment; filename=\"" + path.filename().string() + "\"");
    res.set_content_provider(length, "application/octet-stream",
                             [stream](size_t offset, size_t n, httplib::DataSink& sink) {
                               stream->clear();
                               stream->seekg(offset);
                               char b[65536];
                               while (n) {
                                 size_t len = std::min(n, sizeof b);
                                 if (!stream->read(b, len))
                                   return false;
                                 if (!sink.write(b, len))
                                   return false;
                                 n -= len;
                               }
                               return true;
                             });
  });
  server.Get("/api/export", [&](const auto& req, auto& res) {
    auto mb =
        req.has_param("graph_memory_mb") ? number(req.get_param_value("graph_memory_mb")) : 128;
    if (mb < 8 || mb > 4096)
      throw std::runtime_error("图预算应为 8–4096 MiB");
    auto reader = std::make_shared<StoreReader>(safe_file(dir, req.get_param_value("file")),
                                                mb * 1024ULL * 1024ULL);
    auto first = std::make_shared<bool>(true);
    auto signature = std::make_shared<std::string>();
    res.set_header("Content-Disposition", "attachment; filename=\"chains.txt\"");
    res.set_chunked_content_provider(
        "text/plain; charset=utf-8", [reader, first, signature](size_t, httplib::DataSink& sink) {
          try {
            std::string b;
            Chain c;
            for (int i = 0; i < 200; ++i) {
              if (!reader->next(c)) {
                if (!b.empty())
                  sink.write(b.data(), b.size());
                sink.done();
                return true;
              }
              if (*first || *signature != std::to_string(c.bits) + c.mask) {
                *signature = std::to_string(c.bits) + c.mask;
                J header = {{"bits", c.bits},
                            {"mask", c.mask},
                            {"complete", reader->metadata.value("complete", false)}};
                b += "# CSCAN-TXT 1 " + header.dump() + "\n";
                *first = false;
              }
              b += c.line() + "\n";
            }
            return sink.write(b.data(), b.size());
          } catch (...) {
            return false;
          }
        });
  });
  server.Get("/api/text-download", [&](const auto& req, auto& res) {
    auto path = safe_file(dir, req.get_param_value("file"));
    if (path.extension() != ".txt")
      throw std::runtime_error("文本下载只接受 .txt 结果");
    auto stream = std::make_shared<std::ifstream>(path, std::ios::binary);
    if (!*stream)
      throw std::runtime_error("无法读取文本结果");
    uint64_t length = fs::file_size(path);
    res.set_header("Content-Disposition",
                   "attachment; filename=\"" + path.filename().string() + "\"");
    res.set_content_provider(length, "text/plain; charset=utf-8",
                             [stream](size_t offset, size_t n, httplib::DataSink& sink) {
                               stream->clear();
                               stream->seekg(offset);
                               char b[65536];
                               while (n) {
                                 size_t len = std::min(n, sizeof b);
                                 if (!stream->read(b, len))
                                   return false;
                                 if (!sink.write(b, len))
                                   return false;
                                 n -= len;
                               }
                               return true;
                             });
  });
  server.Get("/api/task", [&](const auto&, auto& res) {
    std::lock_guard<std::mutex> lock(mutex);
    json(res, state);
  });
  server.Post("/api/cancel", [&](const auto&, auto& res) {
    std::lock_guard<std::mutex> lock(mutex);
    if (context && state["status"] == "running")
      context->cancel = true;
    json(res, {{"ok", true}});
  });
  server.Post("/api/demo", [&](const auto&, auto& res) {
    std::lock_guard<std::mutex> lock(mutex);
    if (state["status"] == "running") {
      json(res, {{"error", "请等当前任务结束后再载入样本"}}, 409);
      return;
    }
    if (!fixture)
      fixture = std::make_unique<Fixture>(dir);
    json(res, fixture->info());
  });
  server.Post("/api/task", [&](const auto& req, auto& res) {
    auto request = J::parse(req.body);
    if (!request.is_object())
      throw std::runtime_error("任务参数必须是对象");
    std::lock_guard<std::mutex> lock(mutex);
    if (state["status"] == "running") {
      json(res, {{"error", "已有任务运行中，请等待或取消"}}, 409);
      return;
    }
    if (worker.joinable())
      worker.join();
    context = std::make_shared<Context>();
    auto ctx = context;
    std::string id = unique_id();
    state = {{"status", "running"},
             {"id", id},
             {"kind", request.value("kind", "scan")},
             {"events", J::array()},
             {"started_at", std::time(nullptr)}};
    ctx->event = [&](J event) {
      std::lock_guard<std::mutex> guard(mutex);
      state["progress"] = event;
      auto& ev = state["events"];
      ev.push_back(event);
      if (ev.size() > 120)
        ev.erase(ev.begin());
    };
    worker = std::thread([&, ctx, request] {
      try {
        J result = run(request, dir, *ctx);
        std::lock_guard<std::mutex> guard(mutex);
        auto reason = result.value("reason", "");
        state["status"] = reason == "cancelled"            ? "cancelled"
                          : result.value("complete", true) ? "success"
                                                           : "partial";
        state["result"] = result;
      } catch (const Cancelled&) {
        std::lock_guard<std::mutex> guard(mutex);
        state["status"] = "cancelled";
        state["error"] = "任务已取消，未发布结果";
      } catch (const Budget& e) {
        std::lock_guard<std::mutex> guard(mutex);
        state["status"] = "error";
        state["error"] = std::string("资源上限：") + e.what() + "，本阶段未发布结果";
      } catch (const std::exception& e) {
        std::lock_guard<std::mutex> guard(mutex);
        state["status"] = "error";
        state["error"] = e.what();
      }
    });
    json(res, {{"id", id}}, 202);
  });
  std::cout << "\nC扫指针工具第一版 v" << version << "\n浏览器打开：http://" << host
            << "\n结果目录：" << dir << "\n请保持此终端运行。Ctrl+C 结束服务。\n"
            << std::flush;
  bool ok = server.listen("127.0.0.1", port);
  {
    std::lock_guard<std::mutex> lock(mutex);
    if (context)
      context->cancel = true;
  }
  if (worker.joinable())
    worker.join();
  if (!ok)
    throw std::runtime_error("网页服务启动失败，端口可能已被占用");
  return 0;
}
}  // namespace cs
