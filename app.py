import streamlit as st
import requests
from datetime import datetime

# إعدادات صفحة Streamlit
st.set_page_config(
    page_title="Sentinel Pro - الفحص الأمني الاحترافي",
    page_icon="🛡️",
    layout="centered"
)

# تصميم واجهة السيبيربانك الداكنة
st.markdown("""
    <style>
    .main { background-color: #0b0f19; color: #f9fafb; }
    .stTextInput input { background-color: #111827; color: #fff; border: 1px solid #1f2937; border-radius: 8px; }
    .stButton button { background-color: #10b981; color: #000; font-weight: bold; border-radius: 8px; border: none; width: 100%; }
    .stButton button:hover { background-color: #059669; color: #fff; }
    .header-box { background-color: #111827; border: 1px solid #1f2937; padding: 12px; border-radius: 8px; margin-bottom: 10px; }
    .badge-pass { background-color: rgba(16, 185, 129, 0.2); color: #10b981; padding: 3px 8px; border-radius: 4px; font-weight: bold; font-size: 0.8rem; }
    .badge-fail { background-color: rgba(239, 68, 68, 0.2); color: #ef4444; padding: 3px 8px; border-radius: 4px; font-weight: bold; font-size: 0.8rem; }
    .badge-warn { background-color: rgba(245, 158, 11, 0.2); color: #f59e0b; padding: 3px 8px; border-radius: 4px; font-weight: bold; font-size: 0.8rem; }
    </style>
""", unsafe_allow_html=True)

st.title("🛡️ SENTINEL PRO")
st.caption("محلل رؤوس الأمان ومولّد تقارير سد الثغرات الاحترافي")

# قاعدة بيانات الرؤوس المستهدفة وقواعد الفحص والتأثير
SECURITY_HEADERS = {
    "Content-Security-Policy": {
        "desc": "الحماية ضد هجمات حقن الأكواد وثغرات XSS.",
        "risk": "مخاطر عالية جداً: تسمح برفع وتنفيذ سكريبتات ضارة.",
        "fix": "Header set Content-Security-Policy \"default-src 'self'; script-src 'self'\""
    },
    "Strict-Transport-Security": {
        "desc": "إجبار الاتصال المشفر والآمن عبر HTTPS دائماً.",
        "risk": "مخاطر عالية: عرضة لهجمات اعتراض وتعديل الاتصال (MitM).",
        "fix": "Header set Strict-Transport-Security \"max-age=31536000; includeSubDomains; preload\""
    },
    "X-Frame-Options": {
        "desc": "منع تضمين الموقع داخل إطارات خفية.",
        "risk": "مخاطر متوسطة: عرضة لاختطاف النقر (Clickjacking).",
        "fix": "Header set X-Frame-Options \"DENY\" أو \"SAMEORIGIN\""
    },
    "X-Content-Type-Options": {
        "desc": "منع المتصفح من تخمين وتفسير الملفات بصيغ مغلوطة.",
        "risk": "مخاطر متوسطة: إمكانية تنفيذ ملفات برمجية غير آمنة.",
        "fix": "Header set X-Content-Type-Options \"nosniff\""
    },
    "Referrer-Policy": {
        "desc": "التحكم في تسريب معلومات الإحالة عند تنقل المستخدم.",
        "risk": "مخاطر منخفضة: تسريب مسارات ورابط زيارات حساسة.",
        "fix": "Header set Referrer-Policy \"strict-origin-when-cross-origin\""
    },
    "Permissions-Policy": {
        "desc": "تقييد صلاحيات الكاميرا والميكروفون والموقع الجغرافي.",
        "risk": "مخاطر متوسطة: استغلال ميزات الجهاز بدون إذن واضح.",
        "fix": "Header set Permissions-Policy \"geolocation=(), microphone=(), camera=()\""
    }
}

target_url = st.text_input("أدخل رابط الموقع المستهدف (Target URL):", "https://google.com")

if st.button("⚡ بدء الفحص العميق والتحليل الاحترافي"):
    url = target_url.strip()
    if not url.startswith("http"):
        url = "https://" + url

    with st.spinner("جاري الاتصال بالسيرفر وتتبع المسارات وفحص القيم..."):
        try:
            # طلب HTTP حقيقي مع تتبع التوجيهات
            session = requests.Session()
            response = session.get(url, timeout=10, allow_redirects=True, headers={'User-Agent': 'SentinelPro/2.0 Security Scanner'})
            
            headers_res = response.headers
            missing_headers = []
            weak_headers = []
            passed_headers = []

            # الفحص الدقيق والتحقق من القيم
            for header_name, info in SECURITY_HEADERS.items():
                found_key = next((k for k in headers_res if k.lower() == header_name.lower()), None)
                
                if not found_key:
                    missing_headers.append((header_name, info, "مفقود بالكامل"))
                else:
                    val = headers_res[found_key]
                    if header_name == "Content-Security-Policy" and ("unsafe-inline" in val or "unsafe-eval" in val or "*" in val):
                        weak_headers.append((header_name, info, f"موجود بقيمة ضعيفة: {val}"))
                    else:
                        passed_headers.append((header_name, val))

            # حساب التقييم الاحترافي الفعلي
            score = len(passed_headers)
            if score == 6 and len(weak_headers) == 0:
                grade = "A+"
            elif score >= 5:
                grade = "B"
            elif score >= 3:
                grade = "C"
            elif score >= 2:
                grade = "D"
            else:
                grade = "F"

            st.subheader(f"التقييم الأمني الفعلي: {grade}")
            
            if grade in ["D", "F"]:
                st.error(f"⚠️ تحذير أمني حرج: الموقع يعاني من نقص حاد في بروتوكولات الحماية مما يجعله عرضة للهجمات المباشرة.")
            elif grade in ["B", "C"]:
                st.warning(f"تنبيه: التقييم متوسط، ينصح بتفعيل جميع رؤوس الحماية وتحسين الإعدادات.")
            else:
                st.success("الموقع محمي بشكل ممتاز وحاصل على أعلى المعايير!")

            tab1, tab2 = st.tabs(["🔍 نتائج الفحص الحقيقية", "📄 تقرير الإفصاح ودليل الإصلاح"])

            with tab1:
                st.markdown("### رؤوس الأمان وحالتها الفعلية:")
                
                for h_name, val in passed_headers:
                    st.markdown(f"""
                    <div class="header-box">
                        <div style="display:flex; justify-content:space-between; align-items:center;">
                            <b>{h_name}</b>
                            <span class="badge-pass">مفعل وآمن ✅</span>
                        </div>
                        <small style="color:#9ca3af;">القيمة: {val}</small>
                    </div>
                    """, unsafe_allow_html=True)

                for h_name, info, reason in weak_headers:
                    st.markdown(f"""
                    <div class="header-box">
                        <div style="display:flex; justify-content:space-between; align-items:center;">
                            <b>{h_name}</b>
                            <span class="badge-warn">تحذير: قيمة ضعيفة ⚠️</span>
                        </div>
                        <small style="color:#f59e0b;">{reason}</small><br>
                        <small style="color:#ef4444;">🔴 {info['risk']}</small>
                    </div>
                    """, unsafe_allow_html=True)

                for h_name, info, reason in missing_headers:
                    st.markdown(f"""
                    <div class="header-box">
                        <div style="display:flex; justify-content:space-between; align-items:center;">
                            <b>{h_name}</b>
                            <span class="badge-fail">مفقود ❌</span>
                        </div>
                        <small style="color:#9ca3af;">{info['desc']}</small><br>
                        <small style="color:#ef4444;">🔴 {info['risk']}</small>
                    </div>
                    """, unsafe_allow_html=True)

            with tab2:
                rep = f"=== تقرير إفصاح ثغرات أمنية ودليل الإصلاح الاحترافي ===\n"
                rep += f"تاريخ الفحص: {datetime.now().strftime('%Y-%m-%d %H:%M')}\n"
                rep += f"الموقع المستهدف: {url}\n"
                rep += f"التقييم العام: {grade} ({len(passed_headers)}/6 رؤوس آمنة)\n\n"

                if missing_headers or weak_headers:
                    rep += "[البنود المفقودة والضعيفة وتأثيرها]\n"
                    idx = 1
                    for h_name, info, reason in missing_headers + weak_headers:
                        rep += f"{idx}. {h_name} ({reason})\n   - التأثير: {info['risk']}\n"
                        idx += 1

                    rep += "\n[🛠️ دليل سد الثغرات لصاحب الموقع (Remediation Guide)]\n"
                    rep += "إليك سطور التكوين البرمجية اللازمة لإغلاق هذه الثغرات عبر خادم الويب (Apache / Nginx):\n\n"
                    for h_name, info, reason in missing_headers + weak_headers:
                        rep += f"إصلاح ({h_name}):\n  {info['fix']}\n\n"
                else:
                    rep += "جميع رؤوس الحماية مفعلة بشكل ممتاز وآمن.\n"

                rep += "تم التقييم والفحص المباشر عبر تطبيق Sentinel Pro Real Engine."

                st.text_area("نص التقرير مع حلول سد الثغرات:", value=rep, height=300)
                st.download_button("تنزيل التقرير كملف نصي 📥", data=rep, file_name=f"Sentinel_Report.txt")

        except Exception as e:
            st.error(f"تعذر الاتصال بالموقع أو الفحص. الخطأ: {str(e)}")

