"""Train ScamShield's lightweight on-device text model.
Char n-gram (3-5) binary features over Arabic/English-normalised text -> chi2 selection -> logistic regression.
Exports weights to model.json so the browser computes the exact same score (no server, no data leaves the phone)."""
import csv, json, re, random, sys, pathlib
HERE = pathlib.Path(__file__).resolve().parent
import numpy as np
from sklearn.feature_extraction.text import CountVectorizer
from sklearn.feature_selection import SelectKBest, chi2
from sklearn.linear_model import LogisticRegression
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report, roc_auc_score, confusion_matrix

TASHKEEL = re.compile('[ً-ٟـٰ​‎‏]')
def normalize(t):
    t = TASHKEEL.sub('', t).lower()
    t = re.sub('[أإآٱ]', 'ا', t).replace('ى', 'ي').replace('ة', 'ه').replace('ؤ', 'و').replace('ئ', 'ي')
    t = t.translate(str.maketrans('٠١٢٣٤٥٦٧٨٩۰۱۲۳۴۵۶۷۸۹', '01234567890123456789'))
    t = re.sub(r'\d', '0', t)          # numbers generalise: 482913 -> 000000
    t = re.sub(r'\s+', ' ', t).strip()
    return ' ' + t + ' '

def load(path):
    out = []
    with open(path, encoding='utf8') as f:
        for line in f:
            line = line.rstrip('\n')
            if '\t' not in line: continue
            lab, txt = line.split('\t', 1)
            out.append((1 if lab == 'spam' else 0, txt.replace('\\', '')))
    return out

uci = load(HERE / 'data' / 'sms.tsv'); uae = load(HERE / 'data' / 'uae_synth.tsv')
random.seed(7)
uci_tr, uci_te = train_test_split(uci, test_size=0.2, random_state=7, stratify=[y for y,_ in uci])
uae_tr, uae_te = train_test_split(uae, test_size=0.2, random_state=7, stratify=[y for y,_ in uae])
train = uci_tr + uae_tr
Xtr = [normalize(t) for _, t in train]; ytr = np.array([y for y, _ in train])

K = int(sys.argv[1]) if len(sys.argv) > 1 else 3000
vec = CountVectorizer(analyzer='char', ngram_range=(3, 5), binary=True, min_df=3, lowercase=False)
A = vec.fit_transform(Xtr)
sel = SelectKBest(chi2, k=min(K, A.shape[1])).fit(A, ytr)
feats = np.array(vec.get_feature_names_out())[sel.get_support()]
vec2 = CountVectorizer(analyzer='char', ngram_range=(3, 5), binary=True, lowercase=False, vocabulary=list(feats))
clf = LogisticRegression(C=2.0, max_iter=3000, class_weight='balanced')
clf.fit(vec2.transform(Xtr), ytr)

def ev(name, data):
    X = vec2.transform([normalize(t) for _, t in data]); y = np.array([d[0] for d in data])
    p = clf.predict_proba(X)[:, 1]
    print(f'== {name}  n={len(y)}  AUC={roc_auc_score(y, p):.3f}')
    print(confusion_matrix(y, p >= 0.5))
    print(classification_report(y, p >= 0.5, digits=3, target_names=['legit', 'scam']))
ev('UCI SMS test (English, public benchmark)', uci_te)
ev('UAE synthetic test (AR+EN)', uae_te)

w = clf.coef_[0]
model = {'v': 1, 'ngram': [3, 5], 'bias': round(float(clf.intercept_[0]), 4),
         'w': {f: round(float(x), 4) for f, x in zip(feats, w) if abs(x) > 1e-3}}
json.dump(model, open(HERE / 'model.json', 'w', encoding='utf8'), ensure_ascii=False, separators=(',', ':'))
# reference probabilities for JS parity test
ref = [{'t': t, 'p': float(clf.predict_proba(vec2.transform([normalize(t)]))[0, 1])} for _, t in (uci_te[:40] + uae_te[:40])]
json.dump(ref, open(HERE / 'parity.json', 'w', encoding='utf8'), ensure_ascii=False)
print('features', len(model['w']))
