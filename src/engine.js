/* ScamShield AI — detection engine (rules + on-device ML). Runs in browser and Node. */

// ===================== ScamShield AI detection engine =====================
// Hybrid explainable engine: normalised bilingual (AR/EN) signal detection,
// UAE entity impersonation checks, URL forensics (lookalike / typosquat /
// shorteners / risky TLDs), phone-number origin, and combination rules.

function normalize(t){
  let s='',map=[];
  for(let i=0;i<t.length;i++){
    const code=t.charCodeAt(i);
    if((code>=0x064B&&code<=0x065F)||code===0x0640||code===0x0670||code===0x200F||code===0x200E||code===0x200B)continue;
    let c=t[i].toLowerCase(); if(c.length>1)c=c[0];
    if('أإآٱ'.includes(c))c='ا';
    else if(c==='ى')c='ي';
    else if(c==='ة')c='ه';
    else if(c==='ؤ')c='و';
    else if(c==='ئ')c='ي';
    else if(code>=0x0660&&code<=0x0669)c=String(code-0x0660);
    else if(code>=0x06F0&&code<=0x06F9)c=String(code-0x06F0);
    else if(c==='٫'||c==='،')c=c;
    s+=c;map.push(i);
  }
  return {s,map};
}
function normPlain(t){return normalize(t).s}
function escRe(s){return s.replace(/[.*+?^${}()|[\]\\]/g,'\\$&')}

// ---------- UAE entities & their official domains ----------
const ENTITIES=[
 {id:'adp',en:'Abu Dhabi Police',ar:'شرطة أبوظبي',gov:1,names:['abu dhabi police','ad police','adpolice','شرطه ابوظبي','شرطه ابو ظبي','القياده العامه لشرطه ابوظبي'],domains:['adpolice.gov.ae']},
 {id:'dxbp',en:'Dubai Police',ar:'شرطة دبي',gov:1,names:['dubai police','شرطه دبي'],domains:['dubaipolice.gov.ae','ecrime.ae']},
 {id:'moi',en:'Ministry of Interior',ar:'وزارة الداخلية',gov:1,names:['ministry of interior','moi uae','وزاره الداخليه'],domains:['moi.gov.ae']},
 {id:'icp',en:'ICP (Identity & Citizenship)',ar:'الهيئة الاتحادية للهوية والجنسية',gov:1,names:['icp','federal authority for identity','emirates id','الهويه والجنسيه','الهويه الاماراتيه','بطاقه الهويه'],domains:['icp.gov.ae']},
 {id:'uaepass',en:'UAE PASS',ar:'الهوية الرقمية UAE PASS',gov:1,names:['uae pass','uaepass','الهويه الرقميه'],domains:['uaepass.ae']},
 {id:'tamm',en:'TAMM',ar:'تم',gov:1,names:['tamm'],domains:['tamm.abudhabi','abudhabi.ae']},
 {id:'itc',en:'ITC / Darb',ar:'مركز النقل المتكامل / درب',gov:1,names:['darb','itc abu dhabi','integrated transport centre','درب','مركز النقل المتكامل'],domains:['itc.gov.ae','darb.ae']},
 {id:'rta',en:'RTA / Salik',ar:'هيئة الطرق / سالك',gov:1,names:['rta','salik','سالك','هيئه الطرق'],domains:['rta.ae','salik.ae']},
 {id:'cust',en:'Customs',ar:'الجمارك',gov:1,names:['customs','الجمارك','جمركيه','جمارك'],domains:['adcustoms.gov.ae','dubaicustoms.gov.ae','icp.gov.ae']},
 {id:'cbuae',en:'Central Bank of the UAE',ar:'مصرف الإمارات المركزي',gov:1,names:['central bank','المصرف المركزي','مصرف الامارات المركزي'],domains:['centralbank.ae']},
 {id:'post',en:'Emirates Post',ar:'بريد الإمارات',names:['emirates post','emiratespost','بريد الامارات'],domains:['emiratespost.ae']},
 {id:'aramex',en:'Aramex',ar:'أرامكس',names:['aramex','ارامكس'],domains:['aramex.com']},
 {id:'dhl',en:'DHL',ar:'DHL',names:['dhl'],domains:['dhl.com','dhl.ae']},
 {id:'etisalat',en:'e& / Etisalat',ar:'اتصالات',names:['etisalat','e&','اتصالات'],domains:['etisalat.ae','eand.com','eand.ae']},
 {id:'du',en:'du',ar:'دو',names:[' du ','du telecom','شركه دو'],domains:['du.ae']},
 {id:'fab',en:'First Abu Dhabi Bank',ar:'بنك أبوظبي الأول',bank:1,names:['first abu dhabi bank','fab bank','بنك ابوظبي الاول'],domains:['bankfab.com']},
 {id:'adcb',en:'ADCB',ar:'بنك أبوظبي التجاري',bank:1,names:['adcb','بنك ابوظبي التجاري'],domains:['adcb.com']},
 {id:'enbd',en:'Emirates NBD',ar:'بنك الإمارات دبي الوطني',bank:1,names:['emirates nbd','enbd','الامارات دبي الوطني'],domains:['emiratesnbd.com']},
 {id:'adib',en:'ADIB',ar:'مصرف أبوظبي الإسلامي',bank:1,names:['adib','مصرف ابوظبي الاسلامي'],domains:['adib.ae']},
 {id:'dib',en:'Dubai Islamic Bank',ar:'بنك دبي الإسلامي',bank:1,names:['dubai islamic bank','بنك دبي الاسلامي'],domains:['dib.ae']},
 {id:'mashreq',en:'Mashreq',ar:'بنك المشرق',bank:1,names:['mashreq','المشرق'],domains:['mashreq.com','mashreqbank.com']},
 {id:'adnoc',en:'ADNOC',ar:'أدنوك',names:['adnoc','ادنوك'],domains:['adnoc.ae','adnocdistribution.ae']},
 {id:'etihad',en:'Etihad Airways',ar:'الاتحاد للطيران',names:['etihad airways','الاتحاد للطيران'],domains:['etihad.com']},
 {id:'emirates',en:'Emirates Airline',ar:'طيران الإمارات',names:['emirates airline','fly emirates','طيران الامارات'],domains:['emirates.com']},
 {id:'lulu',en:'LuLu',ar:'لولو',names:['lulu hypermarket','lulu','لولو'],domains:['luluhypermarket.com']},
 {id:'carrefour',en:'Carrefour',ar:'كارفور',names:['carrefour','كارفور'],domains:['carrefouruae.com','mafcarrefour.com']},
 {id:'amazon',en:'Amazon',ar:'أمازون',names:['amazon','امازون'],domains:['amazon.ae','amazon.com']},
 {id:'noon',en:'noon',ar:'نون',names:['noon.com','noon order'],domains:['noon.com']}
];
const OFFICIAL_DOMAINS=[...new Set(ENTITIES.flatMap(e=>e.domains).concat(['gov.ae','u.ae','whatsapp.com','wa.me','google.com','apple.com','microsoft.com','linkedin.com']))];
const BRAND_TOKENS=['adpolice','police','moi','icp','uaepass','tamm','darb','salik','rta','customs','centralbank','emiratespost','aramex','dhl','etisalat','eand','bankfab','adcb','emiratesnbd','enbd','adib','mashreq','adnoc','etihad','emirates','lulu','carrefour','amazon','noon','gov','government','bank','post','fines','fine','uae','dubai','abudhabi'];
const SHORTENERS=['bit.ly','tinyurl.com','t.co','goo.gl','is.gd','cutt.ly','rb.gy','ow.ly','shorturl.at','tiny.cc','rebrand.ly','t.ly','s.id','v.gd','bitly.ws','lnkd.in','surl.li','urlz.fr','qrco.de','linktr.ee'];
const RISKY_TLDS=['xyz','top','online','site','shop','store','live','icu','cc','tk','ml','ga','cf','gq','buzz','club','vip','info','click','link','support','help','services','work','pw','rest','cyou','sbs','cfd','monster','quest','mom','lol','bond','win','loan','men'];
const KNOWN_TLDS=new Set(['com','net','org','ae','info','xyz','top','online','site','shop','store','app','link','live','icu','cc','tk','ml','ga','cf','gq','buzz','club','vip','io','co','me','ly','gl','gd','to','in','pk','ru','cn','biz','pw','work','click','support','help','services','gov','abudhabi','rest','cyou','sbs','cfd','monster','quest','mom','lol','bond','win','loan','men','uk','us','de','sa','qa','om','kw','bh','eg','tv','ws','id','fr','at','li','ai','dev','page','net.ae']);
const SECOND_LEVEL=['gov.ae','co.ae','ac.ae','net.ae','org.ae','sch.ae','mil.ae','co.uk','com.sa','gov.sa','com.pk','co.in','com.eg'];

// ---------- linguistic signals ----------
// cat: urg|cred|pay|imp|link|threat|bait|chan|safe ; type: scam family it points to
const SIGNALS=[
 {id:'urgency',cat:'urg',w:10,
  en:['urgent','urgently','immediately','right away','within \\d+ ?(hours?|hrs?|minutes?|mins?)','within 24','today only','final (notice|warning|reminder)','last (chance|warning|reminder)','act now','expires? (today|soon)','has expired','will (be )?(suspended|blocked|deactivated|cancelled|canceled|closed|frozen|returned)','account (is |has been )?(suspended|blocked|locked|frozen|restricted)','avoid (penalt|suspension|legal)','asap'],
  ar:['عاجل','فورا','فوري','خلال 24','خلال ساعه','خلال ساعات','اليوم فقط','اخر فرصه','اخر تنبيه','انذار نهايي','تنبيه نهايي','سيتم ايقاف','سيتم تجميد','سيتم حظر','سيتم الغاء','سيتم اغلاق','سيتم ارجاع','تم ايقاف','تم تجميد','تم حظر','تم تعليق','موقوف','لتجنب'],
  why:{en:'Pressure & urgency: tries to make you act before thinking.',ar:'ضغط واستعجال: يدفعك للتصرف قبل التفكير.'}},
 {id:'credReq',cat:'cred',w:30,type:'otp',
  en:['(send|share|give|provide|forward|tell|enter|confirm|reply with|type)( us| me)? (the |your )?(otp|one[- ]time (password|code)|verification code|activation code|pin|cvv|password|passcode|card (number|details)|bank details|code (you|we) (received|sent))','(otp|verification code|pin|cvv|password)( that| which)? (you|was) (received|sent to you)','(enter|update|confirm) (your )?(card|cvv|expiry|iban|account number|emirates id number|bank details)','card (number|details)','cvv','expiry date'],
  ar:['ارسل الرمز','ارسل رمز','ارسلي الرمز','ابعث الرمز','ابعث لي الرمز','زودنا بالرمز','زودنا برمز','شارك الرمز','اعطني الرمز','عطني الرمز','الرمز اللي وصلك','الرمز الذي وصلك','الكود اللي وصلك','الرمز المرسل اليك','ادخل رقم البطاقه','ادخال بيانات البطاقه','بيانات البطاقه','رقم البطاقه','الرقم السري','كلمه المرور','رمز cvv','تاريخ انتهاء البطاقه','بياناتك البنكيه','رقم الحساب البنكي'],
  why:{en:'Asks for a code, PIN, password or card details. No real bank, police or government body ever asks for these.',ar:'يطلب رمز تحقق أو رقم سري أو بيانات بطاقة. لا يوجد بنك أو شرطة أو جهة حكومية تطلب ذلك أبداً.'}},
 {id:'credMention',cat:'cred',w:6,
  en:['otp','verification code','one[- ]time password','pin code'],
  ar:['رمز التحقق','رمز otp','الرمز السري','كود التفعيل','رمز التفعيل'],
  why:{en:'Mentions a verification code / OTP.',ar:'يذكر رمز تحقق / OTP.'}},
 {id:'update',cat:'cred',w:14,type:'account',
  en:['(update|verify|validate|confirm|reactivate|unlock|restore) (your )?(account|details|information|info|identity|kyc|emirates id|data|profile)','kyc','emirates id (has )?expired','to avoid (account )?(suspension|closure|blocking)'],
  ar:['تحديث بياناتك','تحديث البيانات','حدث بياناتك','تحديث الحساب','تاكيد الهويه','تاكيد بياناتك','توثيق الحساب','تفعيل حسابك','اعاده تفعيل','الهويه منتهيه','انتهت صلاحيه الهويه','تحديث الهويه'],
  why:{en:'Asks you to "update" or "verify" your account or ID via message, a classic phishing hook.',ar:'يطلب "تحديث" أو "تأكيد" حسابك أو هويتك عبر رسالة، وهو أسلوب تصيّد معروف.'}},
 {id:'payment',cat:'pay',w:14,
  en:['pay(ment)?( now| the| a| your)? (fee|fine|amount|charge|balance)','(small|nominal|processing|delivery|customs|release|redelivery|clearance|registration|activation|admin(istrative)?) (fee|charge|payment)','transfer (the |this )?(money|amount|fee)','(make|pay|send) (a |the )?deposit','deposit (aed|dhs?|\\d|money|the|first)','gift ?cards?','(bitcoin|usdt|crypto) (wallet|address)','pay (via|through|using) (the )?link'],
  ar:['ادفع','دفع رسوم','يرجي السداد','قم بالسداد','سدد','رسوم','تحويل مبلغ','حول مبلغ','قم بايداع','ايداع مبلغ','عربون','بطاقه هدايا','بطاقات هدايا','محفظه بيتكوين','usdt'],
  why:{en:'Asks for a payment or fee.',ar:'يطلب دفع مبلغ أو رسوم.'}},
 {id:'amount',cat:'pay',w:3,
  en:['(aed|dhs?|dirhams?) ?\\d+[\\d.,]*','\\d+[\\d.,]* ?(aed|dhs?|dirhams?)'],
  ar:['درهم'],
  why:{en:'Mentions a money amount.',ar:'يذكر مبلغاً مالياً.'}},
 {id:'threat',cat:'threat',w:14,type:'fine',
  en:['traffic (fine|violation)','unpaid (fine|violation|bill|toll)','outstanding (fine|violation|balance)','(legal|police) action','arrest','warrant','court (case|summons)','case (has been )?(filed|registered|opened) against','you (will|may) be (arrested|fined|prosecuted|deported)','blacklist','travel ban'],
  ar:['مخالفه مروريه','مخالفات مروريه','مخالفه غير مدفوعه','غرامه','غرامات','اجراءات قانونيه','القبض عليك','امر قبض','قضيه ضدك','بلاغ ضدك','دعوى','محكمه','منع سفر','حظر سفر','ترحيل'],
  why:{en:'Threatens fines, legal action or arrest to scare you.',ar:'يهدد بغرامة أو إجراء قانوني أو قبض لتخويفك.'}},
 {id:'prize',cat:'bait',w:16,type:'prize',
  en:['congratulations','congrats','you( have|\'ve)? (won|been selected|been chosen)','winner','lucky (draw|winner)','prize','reward','claim (your|the) (prize|reward|gift|money)','free (gift|iphone|voucher)','cash prize','jackpot'],
  ar:['مبروك','تهانينا','نهنيك','فزت','ربحت','لقد فزت','الفايز','جايزه','جوايز','سحب علي','في السحب','السحب الكبير','تم اختيارك','تم اختيار رقمك','مكافاه','هديه مجانيه','استلم جايزتك','قسيمه'],
  why:{en:'Unexpected prize or reward, the bait in lottery / advance-fee scams.',ar:'جائزة أو مكافأة غير متوقعة، وهي الطُعم في احتيال السحوبات والرسوم المسبقة.'}},
 {id:'job',cat:'bait',w:14,type:'job',
  en:['part[- ]time (job|work|position)','work from home','earn (aed|dhs?)? ?\\d+','(daily|weekly) (income|salary|earnings|payment)','like (videos|posts)','simple (tasks?|online tasks?)','we are hiring','job offer','no experience (needed|required)','commission per (task|order)'],
  ar:['وظيفه','دوام جزيي','عمل من المنزل','العمل من المنزل','دخل يومي','راتب يومي','اربح يوميا','مهام بسيطه','لايك','بدون خبره','فرصه عمل','عموله'],
  why:{en:'Too-good-to-be-true job offer: a common "task scam" that ends with you paying deposits.',ar:'عرض عمل مغرٍ بشكل غير طبيعي: "احتيال المهام" الذي ينتهي بطلب إيداعات منك.'}},
 {id:'invest',cat:'bait',w:16,type:'invest',
  en:['guaranteed (profit|returns?|income)','double your (money|investment)','\\d+ ?% (daily|weekly|monthly) (profit|return)','(crypto|forex|bitcoin|trading) (investment|platform|signals?|expert)','investment opportunity','risk[- ]free','passive income'],
  ar:['ارباح مضمونه','ربح مضمون','عايد مضمون','عوايد مضمونه','ضاعف','استثمار','تداول','عملات رقميه','بيتكوين','فوركس','بدون مخاطره','ارباح يوميه'],
  why:{en:'Promises guaranteed or unrealistic investment returns.',ar:'يعد بأرباح مضمونة أو غير واقعية من الاستثمار.'}},
 {id:'delivery',cat:'bait',w:10,type:'delivery',
  en:['(parcel|package|shipment|delivery|order) (is |has been )?(on hold|held|pending|failed|suspended|returned|could not be delivered)','(incomplete|invalid|wrong) address','redeliver','reschedule (your )?delivery','unable to deliver','delivery attempt'],
  ar:['شحنتك','الشحنه','طردك','الطرد','لم يتم التسليم','تعذر التوصيل','تعذر تسليم','العنوان غير مكتمل','العنوان غير صحيح','اعاده التوصيل','معلقه في','محجوزه'],
  why:{en:'"Your parcel is on hold" story, the most common SMS phishing in the UAE.',ar:'قصة "شحنتك معلّقة"، وهي أكثر رسائل التصيّد انتشاراً في الإمارات.'}},
 {id:'family',cat:'bait',w:16,type:'family',
  en:['(this is|it\'s) my new number','i lost my phone','new number','(mum|mom|dad|bro|brother|sister),? (i|it\'s)','had an accident','in (the )?hospital','need money (urgently|now)','can you (send|transfer) me'],
  ar:['رقمي الجديد','هذا رقمي','ضاع تلفوني','ضاع جوالي','انكسر تلفوني','صار لي حادث','في المستشفى','محتاج فلوس','ابي فلوس ضروري','حول لي','ارسل لي مبلغ','يمه','يبه','اخوي'],
  why:{en:'"Hi, it\'s me, new number" family-emergency story. Call the person on their old number first.',ar:'قصة "أنا قريبك، هذا رقمي الجديد" وطلب مال عاجل. اتصل بالشخص على رقمه القديم أولاً.'}},
 {id:'sextortion',cat:'threat',w:28,type:'blackmail',
  en:['(i|we) (have|recorded) (your )?(video|photos|pictures)','will (publish|post|share|send) (it|them|your)','(intimate|private) (video|photos)','your (contacts|family) will see','pay or'],
  ar:['ساقوم بنشر','سوف انشر','بنشر صورك','فيديو لك','صورك الخاصه','فضيحه','ساقوم بارسال الفيديو','لاهلك','لعايلتك'],
  why:{en:'Blackmail / sextortion pattern. Never pay; report immediately.',ar:'نمط ابتزاز إلكتروني. لا تدفع أبداً وبلّغ فوراً.'}},
 {id:'secrecy',cat:'threat',w:10,
  en:['(don\'t|do not) tell (anyone|anybody|the bank|your family)','keep (this|it) (secret|confidential|between us)','confidential'],
  ar:['لا تخبر احد','لا تقول لاحد','لا تعلم احد','خلها بينا','بيننا فقط','سري للغايه'],
  why:{en:'Asks you to keep it secret, isolating you from people who would warn you.',ar:'يطلب منك الكتمان، ليعزلك عمّن قد يحذّرك.'}},
 {id:'channel',cat:'link',w:6,
  en:['click (the |on the |this )?(link|here|below)','tap (the |on the )?(link|here|below)','open (the|this) link','visit (the |this )?link','(contact|message|chat with) (us|me|our agent) (on|via) (whatsapp|telegram)','whatsapp','telegram'],
  ar:['اضغط على الرابط','اضغط الرابط','اضغط هنا','انقر هنا','افتح الرابط','عبر الرابط','من خلال الرابط','الرابط التالي','تواصل معنا عبر الواتساب','واتساب','واتس','تيليجرام','تلغرام'],
  why:{en:'Pushes you to a link or to WhatsApp/Telegram.',ar:'يدفعك لفتح رابط أو للتواصل عبر واتساب/تيليجرام.'}},
 {id:'protect',cat:'safe',w:-14,
  en:['(do not|don\'t|never) share (this|your|the)? ?(otp|code|pin|password)?','(do not|don\'t|never) share it','(bank|we) will never ask','if (this|it) wasn\'t you','ignore this (message|sms)'],
  ar:['لا تشارك','لا تشاركه','لا تفصح','لن يطلب','لا يطلب البنك','لن نطلب منك','اذا لم تقم','ان لم تقم'],
  why:{en:'Contains a protective warning ("do not share"), typical of genuine bank alerts.',ar:'يحتوي تحذيراً وقائياً ("لا تشارك الرمز")، وهو معتاد في رسائل البنوك الحقيقية.'}}
];

// compile patterns
SIGNALS.forEach(sg=>{
  sg.re=[];
  sg.en.forEach(p=>sg.re.push(new RegExp('(?<![a-z0-9])(?:'+p+')(?![a-z0-9])','gi')));
  sg.ar.forEach(p=>sg.re.push(new RegExp(escRe(normPlain(p)),'g')));
});
const ENTITY_RE=ENTITIES.map(e=>({e,re:e.names.map(n=>{const nn=normPlain(n); return /^[\x00-\x7f ]+$/.test(nn)?new RegExp('(?<![a-z0-9])'+escRe(nn.trim())+'(?![a-z0-9])','gi'):new RegExp(escRe(nn),'g');})}));

// ---------- URL forensics ----------
function lev(a,b){const m=a.length,n=b.length;if(!m)return n;if(!n)return m;let p=Array(n+1).fill(0).map((_,i)=>i);for(let i=1;i<=m;i++){let c=[i];for(let j=1;j<=n;j++)c[j]=Math.min(p[j]+1,c[j-1]+1,p[j-1]+(a[i-1]===b[j-1]?0:1));p=c;}return p[n];}
const HOMO={'0':'o','1':'l','3':'e','4':'a','5':'s','7':'t','8':'b','9':'g','@':'a','$':'s','rn':'m','vv':'w'};
function deHomo(s){let r=s.replace(/rn/g,'m').replace(/vv/g,'w');return r.replace(/[0134579@$8]/g,c=>HOMO[c]||c);}
function regDomain(host){
  const parts=host.split('.');
  if(parts.length<=2)return host;
  const last2=parts.slice(-2).join('.');
  if(SECOND_LEVEL.includes(last2))return parts.slice(-3).join('.');
  return last2;
}
function isOfficial(host){
  return OFFICIAL_DOMAINS.some(d=>host===d||host.endsWith('.'+d));
}
function officialFor(host){return ENTITIES.filter(e=>e.domains.some(d=>host===d||host.endsWith('.'+d)));}

const URL_RE=/\b((?:https?:\/\/|www\.)[^\s<>"'،]+|(?:[a-z0-9-]+\.)+[a-z]{2,}(?::\d+)?(?:\/[^\s<>"'،]*)?|(?:\d{1,3}\.){3}\d{1,3}(?::\d+)?(?:\/[^\s<>"'،]*)?)/gi;
function extractUrls(text){
  const out=[];let m;URL_RE.lastIndex=0;
  while((m=URL_RE.exec(text))){
    let raw=m[1].replace(/[.,;:!?)\]]+$/,'');
    const hasScheme=/^(https?:\/\/|www\.)/i.test(raw);
    const hostPart=raw.replace(/^https?:\/\//i,'').split(/[\/?#:]/)[0].toLowerCase();
    const tld=hostPart.split('.').pop();
    const isIP=/^(\d{1,3}\.){3}\d{1,3}$/.test(hostPart);
    if(!hasScheme&&!isIP&&!KNOWN_TLDS.has(tld))continue;
    if(/^\d+(\.\d+)+$/.test(hostPart)&&!isIP)continue; // amounts like 1.500
    if(!hasScheme&&/@/.test(text.slice(Math.max(0,m.index-1),m.index)))continue; // emails
    out.push({raw,index:m.index,len:raw.length});
  }
  return out;
}
function analyzeUrl(raw){
  const r={raw,host:'',findings:[],pts:0,official:false,entities:[]};
  let u=raw.trim();
  if(!/^[a-z]+:\/\//i.test(u))u='http://'+u;
  let url;try{url=new URL(u);}catch(e){r.findings.push({k:'parse',w:20,en:'Malformed link.',ar:'رابط غير سليم.'});r.pts=20;return r;}
  const host=url.hostname.toLowerCase().replace(/\.$/,'');
  r.host=host;
  const add=(k,w,en,ar)=>{r.findings.push({k,w,en,ar});r.pts+=w;};
  const isIP=/^(\d{1,3}\.){3}\d{1,3}$/.test(host);
  const rd=regDomain(host);
  const sld=rd.split('.')[0];
  if(isOfficial(host)){
    r.official=true; r.entities=officialFor(host);
    const who=r.entities.map(e=>e.en).join(', ');
    add('official',-25,'Official domain'+(who?' of '+who:'')+'.','نطاق رسمي'+(r.entities.length?' لـ '+r.entities.map(e=>e.ar).join('، '):'')+'.');
    if(url.protocol==='http:'&&/^https?:/i.test(raw))add('nohttps',4,'Not using HTTPS.','لا يستخدم اتصالاً آمناً HTTPS.');
    return r;
  }
  if(SHORTENERS.some(s=>host===s||host.endsWith('.'+s)))add('short',22,'Link shortener hides the real destination.','رابط مختصر يخفي الوجهة الحقيقية.');
  if(isIP)add('ip',30,'Uses a raw IP address instead of a domain.','يستخدم عنوان IP بدل اسم موقع.');
  if(host.includes('xn--'))add('puny',30,'Punycode / look-alike characters in the domain.','أحرف مزيفة متشابهة (Punycode) في اسم النطاق.');
  const tld=host.split('.').pop();
  if(RISKY_TLDS.includes(tld))add('tld',16,'Cheap high-abuse domain ending ".'+tld+'".','امتداد نطاق رخيص وكثير الاستخدام في الاحتيال ".'+tld+'".');
  if(url.username||raw.includes('@')&&!/^mailto:/i.test(raw))add('at',25,'Contains "@" trick to hide the real site.','يحتوي خدعة "@" لإخفاء الموقع الحقيقي.');
  const hy=(host.replace(/xn--/g,'').match(/-/g)||[]).length;
  if(hy>=2)add('hyph',10,'Many hyphens in the domain (e.g. pay-fine-uae).','شرطات كثيرة في النطاق (مثل pay-fine-uae).');
  if(host.split('.').length>=5)add('deep',10,'Unusually deep sub-domains.','نطاقات فرعية كثيرة بشكل غير طبيعي.');
  // brand inside domain but not official
  const flat=deHomo(host.replace(/[-.]/g,''));
  const hits=BRAND_TOKENS.filter(t=>t.length>=3&&flat.includes(t));
  const strongHits=hits.filter(t=>!['uae','dubai','abudhabi','bank','post','fine','fines','gov','government'].includes(t));
  if(strongHits.length){
    const ent=ENTITIES.filter(e=>e.domains.some(d=>strongHits.some(t=>d.replace(/\./g,'').includes(t))));
    r.entities=ent;
    add('brand',35,'Uses the name "'+strongHits[0]+'" but is NOT the official site'+(ent[0]?' ('+ent[0].domains[0]+')':'')+'.','يستخدم اسم "'+strongHits[0]+'" لكنه ليس الموقع الرسمي'+(ent[0]?' ('+ent[0].domains[0]+')':'')+'.');
  } else if(hits.length){
    add('brandw',12,'Domain uses official-sounding words ('+hits.slice(0,3).join(', ')+') to look legitimate.','النطاق يستخدم كلمات توحي بأنه رسمي ('+hits.slice(0,3).join('، ')+').');
  }
  if(/gov/.test(host)&&!host.endsWith('.gov.ae')&&!host.endsWith('.gov'))add('fakegov',30,'Pretends to be government, but real UAE government sites end with .gov.ae.','يتظاهر بأنه حكومي، والمواقع الحكومية الحقيقية تنتهي بـ ‎.gov.ae');
  // typosquat
  if(!strongHits.length){
    for(const d of OFFICIAL_DOMAINS){
      const osld=regDomain(d).split('.')[0];
      if(osld.length<4)continue;
      const a=deHomo(sld),dist=lev(a,osld);
      if(sld!==osld&&(dist<=Math.max(1,Math.floor(osld.length/6))||a===osld)){
        const ent=ENTITIES.find(e=>e.domains.includes(d));
        if(ent)r.entities=[ent];
        add('typo',40,'Look-alike of the official domain "'+d+'" (typosquatting).','نطاق مقلّد يشبه النطاق الرسمي "'+d+'".');
        break;
      }
    }
  }
  const path=(url.pathname+url.search).toLowerCase();
  if(/(login|signin|verify|update|secure|account|pay|payment|fine|track|redeliver|confirm|wallet|kyc|otp|card)/.test(path))add('path',8,'Link path asks for login / payment / verification.','مسار الرابط يطلب دخولاً أو دفعاً أو تحققاً.');
  if(url.protocol==='http:'&&/^http:/i.test(raw))add('nohttps',6,'Not using HTTPS.','لا يستخدم اتصالاً آمناً HTTPS.');
  if(/\.(apk|exe|scr|bat|msi)(\?|$)/i.test(url.pathname))add('apk',35,'Downloads an app/executable file. Possible malware.','يُنزّل ملف تطبيق/برنامج، وقد يكون برنامجاً خبيثاً.');
  if(!r.findings.length)add('unknown',6,'Unknown website: not on the official list.','موقع غير معروف وليس ضمن القائمة الرسمية.');
  return r;
}

// ---------- phones ----------
function extractPhones(text){
  const out=[];const re=/(?:\+|00)\s?\d[\d\s-]{7,16}\d|(?<!\d)0?5\d[\s-]?\d{3}[\s-]?\d{4}(?!\d)|wa\.me\/\d+/gi;let m;
  while((m=re.exec(text))){
    const raw=m[0];const digits=raw.replace(/\D/g,'');
    let foreign=false,cc='';
    if(/^(\+|00|wa)/i.test(raw.trim())){
      const d=digits.replace(/^00/,'');
      if(!d.startsWith('971')){foreign=true;cc=d.slice(0,3);}
    }
    out.push({raw,index:m.index,len:raw.length,foreign,cc});
  }
  return out;
}

// ---------- on-device ML model (char n-gram logistic regression, trained in ml/train.py) ----------
const MODEL=(typeof SCAMSHIELD_MODEL!=='undefined')?SCAMSHIELD_MODEL:((typeof require!=='undefined')?(function(){try{return require('./model.js');}catch(e){return null;}})():null);
function mlNormalize(t){
  t=t.replace(/[\u064B-\u065F\u0640\u0670\u200B\u200E\u200F]/g,'').toLowerCase();
  t=t.replace(/[أإآٱ]/g,'ا').replace(/ى/g,'ي').replace(/ة/g,'ه').replace(/ؤ/g,'و').replace(/ئ/g,'ي');
  t=t.replace(/[٠-٩]/g,d=>String(d.charCodeAt(0)-0x0660)).replace(/[۰-۹]/g,d=>String(d.charCodeAt(0)-0x06F0));
  t=t.replace(/[0-9]/g,'0').replace(/\s+/g,' ').trim();
  return ' '+t+' ';
}
function mlScore(text){
  if(!MODEL)return null;
  const s=mlNormalize(text),seen=new Set();let z=MODEL.bias;const top=[];
  for(let n=MODEL.ngram[0];n<=MODEL.ngram[1];n++)for(let i=0;i+n<=s.length;i++){const g=s.substr(i,n);if(seen.has(g))continue;seen.add(g);const w=MODEL.w[g];if(w!==undefined){z+=w;top.push([g,w]);}}
  top.sort((a,b)=>b[1]-a[1]);
  return {p:1/(1+Math.exp(-z)),top:top.slice(0,5).map(x=>x[0].trim()).filter(Boolean)};
}

// ---------- main analysis ----------
const TYPES={
 otp:{en:'OTP / bank-credential theft',ar:'سرقة رمز التحقق / بيانات بنكية'},
 account:{en:'Account-update phishing',ar:'تصيّد "تحديث البيانات"'},
 fine:{en:'Fake fine / government impersonation',ar:'مخالفة وهمية / انتحال جهة حكومية'},
 delivery:{en:'Fake parcel-delivery phishing',ar:'تصيّد شحنة وهمية'},
 prize:{en:'Fake prize / lottery (advance-fee)',ar:'جائزة / سحب وهمي (رسوم مسبقة)'},
 job:{en:'Fake job / task scam',ar:'وظيفة وهمية / احتيال المهام'},
 invest:{en:'Investment / crypto fraud',ar:'احتيال استثمار / عملات رقمية'},
 family:{en:'Impersonating a relative',ar:'انتحال صفة قريب'},
 blackmail:{en:'Blackmail / sextortion',ar:'ابتزاز إلكتروني'},
 phishing:{en:'Phishing link',ar:'رابط تصيّد'},
 none:{en:'No scam pattern found',ar:'لا يوجد نمط احتيال'}
};

function analyzeMessage(text){
  const N=normalize(text);const s=N.s;
  const hits=[];const spans=[];const typePts={};
  let pts=0;
  const addType=(t,w)=>{if(t)typePts[t]=(typePts[t]||0)+w;};
  const fired={};
  SIGNALS.forEach(sg=>{
    let count=0;const matched=[];
    sg.re.forEach(re=>{re.lastIndex=0;let m;while((m=re.exec(s))){if(!m[0].length){re.lastIndex++;continue;}count++;matched.push(m[0]);
      const st=N.map[m.index],en=N.map[m.index+m[0].length-1]+1;spans.push({st,en,cat:sg.cat});}});
    if(count){fired[sg.id]={count,matched};}
  });
  // de-dup: credMention only if credReq not fired
  if(fired.credReq)delete fired.credMention;
  // protective warning suppresses mention but NOT a direct request
  if(fired.protect&&!fired.credReq){delete fired.credMention;}
  if(fired.protect&&fired.credReq){delete fired.protect;}
  // family "brother" words alone shouldn't fire: need money context
  if(fired.family){const strong=fired.family.matched.some(x=>!/^(يمه|يبه|اخوي|mum|mom|dad|bro|brother|sister)/.test(x));if(!strong||!(fired.payment||/(money|فلوس|مبلغ|حول|transfer|send)/.test(s)))delete fired.family;}

  // entities
  const ents=[];
  ENTITY_RE.forEach(({e,re})=>{re.forEach(r=>{r.lastIndex=0;let m;while((m=r.exec(s))){if(!ents.includes(e))ents.push(e);
    const st=N.map[m.index],en=N.map[m.index+m[0].length-1]+1;spans.push({st,en,cat:'imp'});}});});

  // urls & phones
  const urls=extractUrls(text).map(u=>Object.assign(u,{a:analyzeUrl(u.raw)}));
  urls.forEach(u=>spans.push({st:u.index,en:u.index+u.len,cat:u.a.official?'safe':'link'}));
  const phones=extractPhones(text);
  phones.forEach(p=>{if(p.foreign)spans.push({st:p.index,en:p.index+p.len,cat:'link'})});

  for(const id in fired){
    const sg=SIGNALS.find(x=>x.id===id);const c=fired[id].count;
    const w=sg.w+(sg.w>0?Math.min(c-1,2)*sg.w*0.25:0);
    pts+=w;addType(sg.type,Math.max(w,0));
    hits.push({id,cat:sg.cat,w:Math.round(w),en:sg.why.en,ar:sg.why.ar});
  }

  // url scoring
  const badUrls=urls.filter(u=>!u.a.official);
  const offUrls=urls.filter(u=>u.a.official);
  if(badUrls.length){
    const worst=badUrls.reduce((a,b)=>a.a.pts>b.a.pts?a:b);
    const w=Math.min(55,Math.max(8,worst.a.pts));
    pts+=w;addType('phishing',w*0.6);
    hits.push({id:'url',cat:'link',w:Math.round(w),en:'Suspicious link '+worst.a.host+': '+worst.a.findings.map(f=>f.en).join(' '),ar:'رابط مشبوه '+worst.a.host+': '+worst.a.findings.map(f=>f.ar).join(' ')});
  }
  if(offUrls.length&&!badUrls.length){pts-=12;hits.push({id:'offurl',cat:'safe',w:-12,en:'Only links to official domains ('+offUrls.map(u=>u.a.host).join(', ')+').',ar:'الروابط تخص نطاقات رسمية فقط ('+offUrls.map(u=>u.a.host).join('، ')+').'});}

  // AI model signal (blended with the explainable rules)
  const ml=mlScore(text);
  if(ml){
    const pc=Math.round(ml.p*100);
    if(ml.p>=0.5){const w=Math.round(30*(ml.p-0.5)*2);pts+=w;hits.push({id:'ml',cat:'threat',w,en:'AI model: '+pc+'% scam likelihood (language patterns similar to known scams).',ar:'نموذج الذكاء الاصطناعي: احتمال احتيال '+pc+'% (أنماط لغوية مشابهة لرسائل احتيال معروفة).'});}
    else if(ml.p<0.2){const w=-Math.round(10*(0.2-ml.p)/0.2);pts+=w;hits.push({id:'ml',cat:'safe',w,en:'AI model: '+pc+'% scam likelihood (reads like a normal message).',ar:'نموذج الذكاء الاصطناعي: احتمال احتيال '+pc+'% (تشبه الرسائل العادية).'});}
    else hits.push({id:'ml',cat:'urg',w:0,en:'AI model: '+pc+'% scam likelihood (uncertain).',ar:'نموذج الذكاء الاصطناعي: احتمال احتيال '+pc+'% (غير حاسم).'});
  }
  const foreign=phones.filter(p=>p.foreign);
  if(foreign.length){const w=ents.length?18:10;pts+=w;hits.push({id:'phone',cat:'link',w,en:'Foreign phone number (+'+foreign[0].cc+'…)'+(ents.length?' while claiming to be a UAE entity.':'.'),ar:'رقم هاتف أجنبي (+'+foreign[0].cc+'…)'+(ents.length?' رغم ادعاء أنه جهة إماراتية.':'.')});}

  // impersonation
  if(ents.length){
    const linkNotTheirs=badUrls.length>0;
    const govEnt=ents.find(e=>e.gov);const bankEnt=ents.find(e=>e.bank);
    if(linkNotTheirs){
      const w=28;pts+=w;
      const e=ents[0];
      hits.push({id:'imp',cat:'imp',w,en:'Claims to be '+e.en+' but the link is not '+e.domains[0]+'.',ar:'يدّعي أنه '+e.ar+' لكن الرابط ليس '+e.domains[0]+'.'});
      if(govEnt)addType('fine',14);
      if(['post','aramex','dhl'].includes(e.id))addType('delivery',14);
      if(bankEnt)addType('account',8);
    } else if(fired.credReq||fired.payment||foreign.length){
      const w=12;pts+=w;
      hits.push({id:'imp2',cat:'imp',w,en:'Uses the name of '+ents[0].en+' together with a request for money/data.',ar:'يستخدم اسم '+ents[0].ar+' مع طلب مال أو بيانات.'});
    } else {
      hits.push({id:'ent',cat:'imp',w:0,en:'Mentions '+ents.map(e=>e.en).join(', ')+'.',ar:'يذكر '+ents.map(e=>e.ar).join('، ')+'.'});
    }
    if(govEnt&&fired.credReq){pts+=12;hits.push({id:'govcred',cat:'cred',w:12,en:'Government bodies never ask for codes or card details by message.',ar:'الجهات الحكومية لا تطلب الرموز أو بيانات البطاقات عبر الرسائل.'});}
  }

  // combination rules
  const combo=(cond,w,en,ar,type)=>{if(cond){pts+=w;addType(type,w);hits.push({id:'combo',cat:'threat',w,en,ar});}};
  combo(fired.prize&&fired.payment,16,'Prize + "pay a fee to claim" = advance-fee fraud.','جائزة + "ادفع رسوماً لاستلامها" = احتيال الرسوم المسبقة.','prize');
  combo(fired.job&&(fired.payment||fired.invest),16,'Job offer that requires you to pay/deposit = task scam.','عرض عمل يتطلب منك الدفع أو الإيداع = احتيال المهام.','job');
  combo((fired.threat||fired.delivery)&&fired.payment&&badUrls.length,14,'Threat/parcel story + small payment through a link = card-theft phishing.','قصة مخالفة/شحنة + دفع مبلغ بسيط عبر رابط = تصيّد لسرقة البطاقة.',fired.delivery?'delivery':'fine');
  combo(fired.urgency&&(fired.credReq||fired.update)&&(badUrls.length||foreign.length),10,'Urgency + data request + outside link/number.','استعجال + طلب بيانات + رابط أو رقم خارجي.','otp');
  combo(fired.family&&(fired.urgency||fired.secrecy),10,'Relative in trouble + urgency/secrecy.','قريب في ورطة + استعجال أو كتمان.','family');
  if(fired.credReq)addType('otp',20);
  if(fired.update&&!fired.credReq)addType('account',6);

  pts=Math.max(0,pts);
  let score=Math.round(100*(1-Math.exp(-pts/42)));
  if(fired.credReq&&ents.some(e=>e.gov||e.bank))score=Math.max(score,85);
  if(fired.sextortion)score=Math.max(score,85);
  score=Math.min(99,score);
  let level=score>=80?'crit':score>=55?'high':score>=25?'warn':'ok';
  let type='none';
  if(score>=25){const best=Object.entries(typePts).sort((a,b)=>b[1]-a[1])[0];type=best?best[0]:(badUrls.length?'phishing':'none');}
  hits.sort((a,b)=>b.w-a.w);
  return {score,level,type,hits,spans,urls,phones,entities:ents,text,ml};
}

function defang(u){return u.replace(/^http/i,'hxxp').replace(/\./g,'[.]');}
if(typeof module!=='undefined')module.exports={mlScore,mlNormalize,ENTITIES,analyzeMessage,analyzeUrl,extractUrls,extractPhones,normalize,defang,TYPES};
