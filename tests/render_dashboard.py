"""Renders every dashboard view (sample mode) at desktop + phone width; fails on JS errors or horizontal overflow.
Needs: pip install playwright && playwright install chromium"""
import asyncio,sys,pathlib,tempfile
DASH=(pathlib.Path(__file__).resolve().parent.parent/"cc"/"dashboard.html").as_uri()
OUT=tempfile.mkdtemp(prefix="cc-shots-")
from playwright.async_api import async_playwright
async def main():
    async with async_playwright() as p:
        b=await p.chromium.launch(args=["--no-sandbox"])
        for w,h,tag in ((1280,900,"d"),(390,844,"m")):
            pg=await b.new_page(viewport={"width":w,"height":h}); errs=[]
            pg.on("pageerror",lambda e:errs.append(str(e))); pg.on("console",lambda m: m.type=="error" and errs.append(m.text))
            await pg.goto(DASH)
            await pg.wait_for_timeout(500)
            for v in ["command","red","blue","purple","white","green"]:
                await pg.evaluate(f"location.hash='{v}'"); await pg.wait_for_timeout(200)
                await pg.screenshot(path=f"{OUT}/{tag}_{v}.png",full_page=(tag=="d"))
            sc=await pg.evaluate("[document.getElementById('w_red').textContent,document.getElementById('w_blue').textContent]")
            ov=await pg.evaluate("document.documentElement.scrollWidth")
            print(tag,"errors:",errs,"score red/blue:",sc,"scrollWidth:",ov)
            assert not errs and ov<=w and sc==["20","81"], (tag,errs,ov,sc)
        await b.close()
    print("screenshots in",OUT)
asyncio.run(main())
