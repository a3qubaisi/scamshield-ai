"""End-to-end browser test of the app (both builds, phone + desktop sizes, offline).
Run: pip install playwright && playwright install chromium && python3 tests/e2e_browser.py"""
import sys, pathlib
ROOT=pathlib.Path(__file__).resolve().parent.parent
CHROME=None  # set to a Chrome path if Playwright's bundled browser is not installed
from playwright.sync_api import sync_playwright
results=[]
def ok(c,m):
    results.append((c,m)); print(('PASS ' if c else 'FAIL ')+m)
for target in [(ROOT/'dist'/'scamshield.html').as_uri(),(ROOT/'index.html').as_uri()]:
  for vp in [(390,844),(1440,900)]:
    tag=f"[{target.split('/')[-1]} {vp[0]}px]"
    with sync_playwright() as p:
      b=p.chromium.launch(**({'executable_path':CHROME} if CHROME else {}),args=['--no-sandbox'])
      ctx=b.new_context(viewport={'width':vp[0],'height':vp[1]},accept_downloads=True,permissions=['clipboard-read','clipboard-write'])
      pg=ctx.new_page(); errs=[]; dialogs=[]
      pg.on('pageerror',lambda e:errs.append(str(e))); pg.on('console',lambda m:errs.append(m.text) if m.type=='error' else None)
      pg.on('dialog',lambda d:(dialogs.append(d.message),d.dismiss()))
      pg.goto(target); pg.wait_for_timeout(300)
      ok(pg.evaluate("typeof SCAMSHIELD_MODEL==='object' && Object.keys(SCAMSHIELD_MODEL.w).length>2000"),tag+' AI model loaded')
      ok(pg.get_attribute('html','dir')=='rtl',tag+' Arabic RTL default')
      ok('MADE BY' not in pg.content(),tag+' no MADE BY credit')
      # empty scan
      pg.click('#scanBtn'); ok(pg.is_hidden('#result'),tag+' empty input shows no result')
      exp={0:'crit',1:'crit',2:'crit',3:'crit',4:'high',5:'crit',6:'crit',7:'ok',8:'ok'}
      for i,lv in exp.items():
        pg.click(f'[data-s="{i}"]'); pg.wait_for_timeout(120)
        sc=int(pg.inner_text('#score')); scam=sc>=55
        ok(scam==(lv!='ok'),f'{tag} sample {i} score {sc}')
        ok(pg.locator('#reasons li').count()>0,f'{tag} sample {i} has reasons')
        ok(pg.is_visible('#reportCard')==(lv!='ok'),f'{tag} sample {i} report card visibility')
      # report content & links
      pg.click('[data-s="1"]'); rep=pg.inner_text('#report')
      ok('hxxps' in rep and '[.]' in rep and 'https://emiratespost' not in rep,tag+' report links defanged')
      ok(pg.get_attribute('#callAman','href')=='tel:8002626',tag+' call Aman link')
      ok(pg.get_attribute('#smsAman','href').startswith('sms:2828'),tag+' SMS 2828 link')
      ok(pg.get_attribute('#mailAman','href').startswith('mailto:aman@adpolice.gov.ae?subject='),tag+' email Aman link')
      pg.click('#copyRep'); pg.wait_for_timeout(200)
      ok(pg.evaluate("navigator.clipboard.readText()")==rep,tag+' copy report to clipboard')
      # paste button
      pg.evaluate("navigator.clipboard.writeText('Your OTP is 123456. Do not share it.')"); pg.click('#pasteBtn'); pg.wait_for_timeout(200)
      ok(pg.input_value('#msg').startswith('Your OTP') and int(pg.inner_text('#score'))<25,tag+' paste button scans clipboard')
      # XSS
      pg.fill('#msg','<img src=x onerror="alert(1)"><script>alert(2)</script> http://evil.xyz/<b>x</b>'); pg.click('#scanBtn'); pg.wait_for_timeout(300)
      ok(not dialogs and pg.locator('#hl img').count()==0,tag+' pasted HTML is not executed (XSS safe)')
      # clear
      pg.click('#clearBtn'); ok(pg.input_value('#msg')=='' and pg.is_hidden('#result'),tag+' clear button')
      # ctrl+enter
      pg.fill('#msg','Congratulations you won AED 50,000, pay fee AED 99 to claim bit.ly/x'); pg.press('#msg','Control+Enter'); pg.wait_for_timeout(200)
      ok(pg.is_visible('#result'),tag+' Ctrl+Enter scans')
      # language
      pg.click('#langBtn'); ok(pg.get_attribute('html','dir')=='ltr' and 'Scan now' in pg.inner_text('#scanBtn'),tag+' switch to English')
      ok('Why this verdict' in pg.inner_text('#result'),tag+' result re-rendered in English')
      pg.click('#langBtn'); ok(pg.get_attribute('html','dir')=='rtl',tag+' switch back to Arabic')
      # big text
      pg.click('#bigBtn'); ok(pg.evaluate("document.body.classList.contains('big')"),tag+' large text mode on'); pg.click('#bigBtn')
      # link tab
      pg.click('[data-tab="link"]'); ok(pg.is_visible('#tab-link') and pg.is_hidden('#tab-scan'),tag+' link tab opens')
      for u,bad in [('https://adpolice.gov.ae',False),('http://uaepass-login.com/verify',True),('https://emlratesnbd.com',True),('https://tamm-gov-ae.online/fines',True),('http://185.243.11.4/aramex/pay',True)]:
        pg.click(f'[data-u="{u}"]'); pg.wait_for_timeout(100); sc=int(pg.inner_text('#uscore'))
        ok((sc>=55)==bad,f'{tag} link {u} score {sc}')
      pg.click('[data-u="bit.ly/3xYz9Q"]'); pg.wait_for_timeout(100); sc=int(pg.inner_text('#uscore'))
      ok(25<=sc<55 and pg.inner_text('#ulevel') in ('مشبوه','Suspicious'),f'{tag} short link flagged suspicious ({sc})')
      pg.fill('#urlIn','https://www.dhl.com/ae-en'); pg.press('#urlIn','Enter'); pg.wait_for_timeout(100)
      ok(int(pg.inner_text('#uscore'))<25,tag+' typed official link + Enter is safe')
      # intel
      pg.click('[data-tab="intel"]'); stats=pg.inner_text('#stats')
      ok(pg.locator('#iocs tr').count()>=3,tag+' intel board lists indicators')
      ok(pg.locator('#typeBars .bar').count()>=3,tag+' intel scam-type chart')
      with pg.expect_download() as d: pg.click('#csvBtn')
      csv=open(d.value.path(),encoding='utf-8-sig').read()
      ok(csv.startswith('"indicator","kind","seen"') and '[.]' in csv,tag+' CSV export works and is defanged')
      # persistence
      pg.reload(); pg.click('[data-tab="intel"]')
      ok(pg.locator('#iocs tr').count()>=3,tag+' intel persists after reload')
      pg.click('#resetBtn'); ok('0' in pg.inner_text('#stats').split()[0],tag+' reset clears intel')
      # learn
      pg.click('[data-tab="learn"]'); ok(pg.locator('#tips .tip').count()==8 and '8002626' in pg.inner_text('#contacts'),tag+' awareness tab')
      # horizontal overflow
      ok(pg.evaluate("document.documentElement.scrollWidth<=window.innerWidth+1"),tag+' no sideways scrolling')
      ok(not errs,tag+' no JavaScript errors '+str(errs[:2]))
      b.close()
# offline (no network at all)
with sync_playwright() as p:
  b=p.chromium.launch(**({'executable_path':CHROME} if CHROME else {}),args=['--no-sandbox'])
  ctx=b.new_context(offline=True); pg=ctx.new_page(); reqs=[]
  pg.on('request',lambda r:reqs.append(r.url) if not r.url.startswith(('file:','data:','blob:')) else None)
  pg.goto((ROOT/'dist'/'scamshield.html').as_uri()); pg.click('[data-s="0"]'); pg.wait_for_timeout(300)
  ok(int(pg.inner_text('#score'))>=80,'[offline] works with no internet')
  ok(not reqs,'[offline] zero network requests '+str(reqs[:3]))
  b.close()
f=[m for c,m in results if not c]
print(f'\n{len(results)-len(f)}/{len(results)} browser checks passed'); sys.exit(1 if f else 0)
