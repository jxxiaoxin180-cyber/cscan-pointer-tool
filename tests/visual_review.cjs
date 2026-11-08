const {chromium}=require(process.env.PLAYWRIGHT_MODULE||'/tmp/ahwbp-ui-check/node_modules/playwright');
const {spawn}=require('child_process');
(async()=>{
 const proc=spawn('./build-android/cscan',['serve','--port','18763','--data','./build-host/visual-data']);
 const browser=await chromium.launch({executablePath:'/root/.cache/ms-playwright/chromium-1243/chrome-linux-arm64/chrome',headless:true,args:['--no-sandbox','--disable-dev-shm-usage']});
 try{const page=await browser.newPage({viewport:{width:390,height:844},deviceScaleFactor:1});await page.goto('http://127.0.0.1:18763');await page.waitForFunction(()=>document.querySelector('#connection').textContent==='引擎已连接');await page.screenshot({path:'artifacts/screenshots/mobile-viewport-review.png'});
 console.log(await page.evaluate(()=>[...document.querySelectorAll('.sidebar,.sidebar nav,.nav-item')].map(e=>({text:e.textContent.trim(),rect:JSON.stringify(e.getBoundingClientRect()),display:getComputedStyle(e).display,color:getComputedStyle(e).color,visibility:getComputedStyle(e).visibility}))));}
 finally{await browser.close();proc.kill();}
})().catch(e=>{console.error(e);process.exit(1)});
