"""Generate a synthetic bilingual (Arabic/English) UAE scam / legitimate SMS corpus.
Templates are written from public UAE police awareness patterns. Output: data/uae_synth.tsv (label\ttext)."""
import random, csv, pathlib
HERE = pathlib.Path(__file__).resolve().parent
random.seed(42)

ENT_GOV = [("Abu Dhabi Police","شرطة أبوظبي"),("Dubai Police","شرطة دبي"),("ICP","الهيئة الاتحادية للهوية والجنسية"),
           ("Ministry of Interior","وزارة الداخلية"),("UAE PASS","الهوية الرقمية"),("RTA","هيئة الطرق والمواصلات"),("Salik","سالك"),("Darb","درب"),("TAMM","تم")]
ENT_BANK = [("FAB","بنك أبوظبي الأول"),("ADCB","بنك أبوظبي التجاري"),("Emirates NBD","بنك الإمارات دبي الوطني"),("ADIB","مصرف أبوظبي الإسلامي"),("Mashreq","بنك المشرق"),("DIB","بنك دبي الإسلامي")]
ENT_POST = [("Emirates Post","بريد الإمارات"),("Aramex","أرامكس"),("DHL","دي إتش إل"),("FedEx","فيديكس")]
ENT_BRAND = [("ADNOC","أدنوك"),("Etisalat","اتصالات"),("du","دو"),("Carrefour","كارفور"),("LuLu","لولو"),("Etihad","الاتحاد للطيران"),("Emirates","طيران الإمارات")]
BAD_TLD = ["xyz","top","online","site","shop","cc","info","live","click","link","icu","vip"]
SHORT = ["bit.ly","tinyurl.com","cutt.ly","rb.gy","is.gd","t.ly"]
FOREIGN = ["+92 3","+234 80","+44 74","+63 91","+62 81","+880 17","+1 202","+212 6"]
WORDS = ["pay","fine","secure","update","verify","track","gov","uae","login","portal","service","online","redeliver"]

def amt(lo=3,hi=500): return random.choice([str(random.randint(lo,hi)), f"{random.randint(lo,hi)}.{random.choice(['00','50','99'])}"])
def bigamt(): return random.choice(["10,000","25,000","50,000","100,000","1,000,000","75,000"])
def slug(name): return name.lower().replace(" ","").replace("uaepass","uaepass")
def bad_url(name=None):
    k=random.random()
    if k<0.25: return f"https://{random.choice(SHORT)}/{''.join(random.choices('abcdefghijkmnpqrstuvwxyz23456789',k=6))}"
    base = slug(name) if name else random.choice(WORDS)
    parts=[base, random.choice(WORDS)]; random.shuffle(parts)
    dom="-".join(parts)
    if random.random()<0.3: dom+= "-ae"
    path=random.choice(["","/pay","/verify","/login","/track?id="+str(random.randint(1000,99999)),"/update"])
    return f"{random.choice(['https://','http://',''])}{dom}.{random.choice(BAD_TLD)}{path}"
def fphone():
    # Deliberately fake numbers (all zeros) so no real person's number appears in the data.
    # random.choices is still called so the dataset stays reproducible.
    p=random.choice(FOREIGN); random.choices("0123456789",k=7); return p+"0000000"
def hrs(): return random.choice(["24","12","48","2"])

SCAM_EN = [
 lambda: f"{random.choice(ENT_GOV)[0]}: You have an unpaid traffic fine of AED {amt(100,3000)}. Pay within {hrs()} hours to avoid legal action: {bad_url(random.choice(['adpolice','moi','rta','fines']))}",
 lambda: f"{random.choice(ENT_GOV)[0]}: Your Emirates ID has expired. Update your details now to avoid a fine: {bad_url('icp')}",
 lambda: f"{random.choice(ENT_POST)[0]}: Your parcel is on hold due to an incomplete address. Pay AED {amt(3,15)} redelivery fee: {bad_url(random.choice(['emiratespost','aramex','dhl']))}",
 lambda: f"Your package could not be delivered. Reschedule delivery and pay customs fee AED {amt(5,40)} here {bad_url()}",
 lambda: f"Dear customer, your {random.choice(ENT_BANK)[0]} card has been blocked. Share the OTP sent to you to reactivate it.",
 lambda: f"{random.choice(ENT_BANK)[0]} alert: your account will be suspended today. Verify your identity {bad_url(random.choice(['bank','secure','fab','adcb']))}",
 lambda: f"Congratulations! Your number won AED {bigamt()} in the {random.choice(ENT_BRAND)[0]} lucky draw. To claim pay a processing fee of AED {amt(50,300)}. WhatsApp {fphone()}",
 lambda: f"You have been selected as the winner of a free iPhone from {random.choice(ENT_BRAND)[0]}! Claim your reward now: {bad_url()}",
 lambda: f"Part-time job! Earn AED {random.choice(['300','500','800','1200'])} daily by liking videos. No experience needed. Contact wa.me/{fphone().replace(' ','').replace('+','')}",
 lambda: f"We are hiring for simple online tasks, commission per task, daily payment. Deposit AED {amt(100,1000)} to start. Telegram @{random.choice(['hr_uae','jobs_dxb','task_team'])}",
 lambda: f"Guaranteed profit {random.randint(5,30)}% daily with our crypto trading platform. Risk-free, double your money: {bad_url()}",
 lambda: f"Investment opportunity: forex expert signals, guaranteed returns. Join now {bad_url()}",
 lambda: f"Hi mum, this is my new number, I lost my phone. I need money urgently, can you transfer AED {amt(500,5000)} today? Don't tell dad",
 lambda: f"I have recorded your private video. Pay {amt(1000,9000)} AED in bitcoin or I will send it to your family and contacts.",
 lambda: f"{random.choice(ENT_BRAND)[0]}: Your account will be deactivated. Update your information within {hrs()} hours: {bad_url(random.choice(['etisalat','du','adnoc']))}",
 lambda: f"Final notice: unpaid Salik toll AED {amt(4,80)}. Pay now to avoid penalty {bad_url('salik')}",
 lambda: f"This is {random.choice(ENT_GOV)[0]}. A case has been filed against you. Call {fphone()} immediately to avoid arrest.",
 lambda: f"Your UAE PASS account is restricted. Confirm your Emirates ID number and card details at {bad_url('uaepass')}",
]
SCAM_AR = [
 lambda: f"{random.choice(ENT_GOV)[1]}: لديك مخالفة مرورية غير مدفوعة بقيمة {amt(100,3000)} درهم. يرجى السداد خلال {hrs()} ساعة لتجنب الإجراءات القانونية: {bad_url(random.choice(['adpolice','moi','fines']))}",
 lambda: f"{random.choice(ENT_GOV)[1]}: انتهت صلاحية الهوية، قم بتحديث بياناتك فوراً لتجنب الغرامة {bad_url('icp')}",
 lambda: f"{random.choice(ENT_POST)[1]}: شحنتك معلقة بسبب العنوان غير مكتمل. ادفع رسوم إعادة التوصيل {amt(3,15)} درهم عبر الرابط {bad_url('emiratespost')}",
 lambda: f"تعذر توصيل طردك، يرجى دفع الرسوم الجمركية {amt(5,40)} درهم من خلال الرابط التالي {bad_url()}",
 lambda: f"مرحبا معك موظف {random.choice(ENT_BANK)[1]}، تم تجميد بطاقتك. ارسل الرمز اللي وصلك الحين عشان نفعل الحساب",
 lambda: f"عميلنا العزيز سيتم إيقاف حسابك في {random.choice(ENT_BANK)[1]}، اضغط على الرابط لتحديث بياناتك {bad_url('bank')}",
 lambda: f"مبروك! ربحت {bigamt()} درهم في سحب {random.choice(ENT_BRAND)[1]}. لاستلام جائزتك ادفع رسوم {amt(50,300)} درهم وتواصل واتساب {fphone()}",
 lambda: f"تهانينا تم اختيار رقمك للفوز بجائزة من {random.choice(ENT_BRAND)[1]}، استلم جائزتك الآن {bad_url()}",
 lambda: f"وظيفة دوام جزئي من المنزل، اربح {random.choice(['300','500','800'])} درهم يومياً بمهام بسيطة. بدون خبرة. تواصل عبر الواتساب {fphone()}",
 lambda: f"فرصة عمل! عمولة على كل مهمة ودخل يومي، قم بإيداع {amt(100,1000)} درهم للبدء",
 lambda: f"استثمار في العملات الرقمية بأرباح مضمونة {random.randint(5,30)}% يومياً بدون مخاطرة، سجل الآن {bad_url()}",
 lambda: f"هلا {random.choice(['يبه','يمه','اخوي'])} هذا رقمي الجديد ضاع تلفوني، محتاج فلوس ضروري حول لي {amt(500,5000)} درهم ولا تقول لاحد",
 lambda: f"عندي فيديو لك وصورك الخاصة، إذا ما حولت {amt(1000,9000)} درهم سأقوم بنشر الفيديو لأهلك",
 lambda: f"{random.choice(ENT_BRAND)[1]}: سيتم إيقاف خطك خلال {hrs()} ساعة، قم بتحديث بياناتك {bad_url('etisalat')}",
 lambda: f"إنذار نهائي من {random.choice(ENT_GOV)[1]}: يوجد بلاغ ضدك، اتصل فوراً على {fphone()} لتجنب القبض عليك",
 lambda: f"الهوية الرقمية: تم تعليق حسابك، ادخل رقم البطاقة ورمز التحقق لإعادة التفعيل {bad_url('uaepass')}",
]
HAM_EN = [
 lambda: f"Your OTP for {random.choice(ENT_BANK)[0]} online transaction of AED {amt(10,900)} is {random.randint(100000,999999)}. Do not share this code with anyone.",
 lambda: f"AED {amt(1000,30000)} salary credited to your account ending {random.randint(1000,9999)}. Available balance AED {amt(1000,50000)}.",
 lambda: f"Your card ending {random.randint(1000,9999)} was used for AED {amt(5,600)} at {random.choice(['Carrefour','LuLu','ADNOC','Noon','Talabat','Starbucks'])}. If this wasn't you call the number on your card.",
 lambda: f"Aramex: Your shipment {random.randint(1000000,9999999)} will be delivered today between {random.randint(9,14)}-{random.randint(15,21)}. Track on https://www.aramex.com/track",
 lambda: f"Emirates Post: your item has been delivered. Thank you. emiratespost.ae",
 lambda: f"Reminder: your appointment at {random.choice(['SKMC','Cleveland Clinic','NMC','the dental clinic'])} is tomorrow at {random.randint(8,17)}:00. Reply C to confirm.",
 lambda: f"Abu Dhabi Police: Drive safely in foggy weather and reduce your speed. adpolice.gov.ae",
 lambda: f"TAMM: Your payment of AED {amt(50,900)} was received successfully. Reference {random.randint(100000,999999)}.",
 lambda: f"Your Salik account was charged AED 4 at {random.choice(['Al Maktoum Bridge','Al Garhoud','Jebel Ali'])}. Balance AED {amt(10,200)}.",
 lambda: random.choice(["Hey, are we still meeting at 8?","I sent you the presentation, check your email","Can you pick up the kids today?","Running 10 min late, sorry","Happy birthday bro! have a great one","Let's have lunch tomorrow at the office","Did you finish the report for the manager?","Thanks for yesterday, see you on Sunday"]),
 lambda: f"Etihad: Your flight EY{random.randint(100,999)} to {random.choice(['London','Cairo','Mumbai','Paris'])} is on time. Check in at etihad.com",
 lambda: f"Your Talabat order from {random.choice(['Shake Shack','Operation Falafel','Pizza Hut'])} is on the way. Estimated arrival {random.randint(10,40)} min.",
 lambda: f"du: Your bill of AED {amt(100,600)} is due on {random.randint(1,28)}/{random.randint(1,12)}. Pay through the du app or du.ae",
]
HAM_AR = [
 lambda: f"رمز التحقق الخاص بك هو {random.randint(100000,999999)}. لا تشارك هذا الرمز مع أي شخص.",
 lambda: f"تم إيداع راتبك {amt(3000,30000)} درهم في حسابك المنتهي بـ {random.randint(1000,9999)}",
 lambda: f"تم سحب مبلغ {amt(100,2000)} درهم من حسابك عبر الصراف الآلي",
 lambda: f"عزيزي العميل، تم استلام دفعتك بقيمة {amt(50,900)} درهم بنجاح. شكراً لاستخدامك تطبيق تم",
 lambda: random.choice(["هلا، نتقابل الساعة 8 في المطعم؟","السلام عليكم، شو أخبارك؟","وصلت البيت الحمدلله","لا تنسى تجيب الخبز وأنت راجع","مبروك الوظيفة الجديدة، الله يوفقك","الاجتماع بكرة الساعة 10 الصبح","يعطيك العافية على الشغل اليوم","ارسلت لك الملف على الإيميل","تعال الغدا عندنا يوم الجمعة","حبيبي كيف الامتحان اليوم؟"]),
 lambda: f"شرطة أبوظبي: نرجو منكم القيادة بحذر أثناء الضباب والالتزام بالسرعات المحددة",
 lambda: f"تم تأكيد موعدك في {random.choice(['مستشفى خليفة','مركز الخدمة','العيادة'])} يوم {random.choice(['الأحد','الاثنين','الثلاثاء'])} الساعة {random.randint(8,16)}",
 lambda: f"أرامكس: سيتم توصيل شحنتك رقم {random.randint(1000000,9999999)} اليوم. تتبع الشحنة عبر aramex.com",
 lambda: f"تم استخدام بطاقتك المنتهية بـ {random.randint(1000,9999)} بمبلغ {amt(5,600)} درهم لدى {random.choice(['كارفور','لولو','أدنوك'])}",
 lambda: f"اتصالات: فاتورتك بقيمة {amt(100,600)} درهم مستحقة، يمكنك الدفع عبر التطبيق",
]
rows=[]
for _ in range(700): rows.append(("spam", random.choice(SCAM_EN)()))
for _ in range(700): rows.append(("spam", random.choice(SCAM_AR)()))
for _ in range(700): rows.append(("ham", random.choice(HAM_EN)()))
for _ in range(700): rows.append(("ham", random.choice(HAM_AR)()))
rows=list(dict.fromkeys(rows))
with open(HERE / "data" / "uae_synth.tsv","w",encoding="utf8",newline="") as f:
    w=csv.writer(f,delimiter="\t",quoting=csv.QUOTE_NONE,escapechar="\\")
    for r in rows: w.writerow(r)
print(len(rows), sum(1 for r in rows if r[0]=='spam'))
