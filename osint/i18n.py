"""
Helix: the words of the local web page in six languages.

English is the source. Hindi, Spanish, Arabic, Portuguese and Russian were
written with the English next to them and have not yet been checked by a
native speaker of each: corrections are welcome as pull requests. A key
missing from a language falls back to English, and a test fails if a
language lacks a key.
"""

LANGUAGES = {"en": "English", "hi": "हिन्दी", "es": "Español", "ar": "العربية",
             "pt": "Português", "ru": "Русский"}
RTL = {"ar"}

TEXT = {
    "en": {
        "title": "Helix: find the accounts under a username",
        "intro": "Checks a username on many sites and reports only accounts it could confirm. "
                 "Everything runs on this computer.",
        "username": "Username", "purpose": "Why are you looking this name up?",
        "purpose_hint": "For example: my own accounts",
        "sources": "Where to look", "builtin": "56 well-known sites (fast)",
        "all": "Every source, about 12,000 sites (several minutes)",
        "scan": "Check", "scanning": "Checking. Keep this page open.",
        "found": "Accounts found", "none": "No account found on the sites that answered.",
        "answered": "sites answered", "unanswered": "sites gave no clear answer. An account there would not be found.",
        "left_out": "sites were left out because the daily check found them dead or broken.",
        "unconfirmed": "Not confirmed (a made-up name of the same length was also found)",
        "grade": "Same person?", "site": "Site", "address": "Address",
        "refused": "This name is on the left-out list. Its owner asked not to be looked up.",
        "invalid": "That is not a username. Use letters, digits, dot, underscore and hyphen.",
        "responsible": "Look up your own name, or someone who agreed, or have a lawful reason you can explain.",
        "language": "Language", "error": "The check failed",
    },
    "hi": {
        "title": "Helix: किसी यूज़रनेम के खाते खोजें",
        "intro": "एक यूज़रनेम को कई साइटों पर जाँचता है और केवल वही खाते बताता है जिनकी पुष्टि हो सकी। "
                 "सब कुछ इसी कंप्यूटर पर चलता है।",
        "username": "यूज़रनेम", "purpose": "आप यह नाम क्यों खोज रहे हैं?",
        "purpose_hint": "उदाहरण: मेरे अपने खाते",
        "sources": "कहाँ खोजें", "builtin": "56 जानी-मानी साइटें (तेज़)",
        "all": "हर स्रोत, लगभग 12,000 साइटें (कुछ मिनट)",
        "scan": "जाँचें", "scanning": "जाँच चल रही है। यह पेज खुला रखें।",
        "found": "मिले हुए खाते", "none": "जिन साइटों ने जवाब दिया उन पर कोई खाता नहीं मिला।",
        "answered": "साइटों ने जवाब दिया", "unanswered": "साइटों ने साफ़ जवाब नहीं दिया। वहाँ का खाता नहीं मिलेगा।",
        "left_out": "साइटें छोड़ी गईं क्योंकि रोज़ की जाँच में वे बंद या ख़राब मिलीं।",
        "unconfirmed": "पुष्टि नहीं हुई (उतनी ही लंबाई का एक बनावटी नाम भी मिला)",
        "grade": "वही व्यक्ति?", "site": "साइट", "address": "पता",
        "refused": "यह नाम छोड़े गए नामों की सूची में है। इसके मालिक ने कहा है कि इसे न खोजा जाए।",
        "invalid": "यह यूज़रनेम नहीं है। अक्षर, अंक, बिंदु, अंडरस्कोर और हाइफ़न इस्तेमाल करें।",
        "responsible": "अपना नाम खोजें, या किसी ऐसे व्यक्ति का जिसने सहमति दी हो, या कोई वैध कारण रखें जिसे आप बता सकें।",
        "language": "भाषा", "error": "जाँच नहीं हो सकी",
    },
    "es": {
        "title": "Helix: encuentra las cuentas de un nombre de usuario",
        "intro": "Comprueba un nombre de usuario en muchos sitios y solo informa de las cuentas que pudo confirmar. "
                 "Todo se ejecuta en este ordenador.",
        "username": "Nombre de usuario", "purpose": "¿Por qué buscas este nombre?",
        "purpose_hint": "Por ejemplo: mis propias cuentas",
        "sources": "Dónde buscar", "builtin": "56 sitios conocidos (rápido)",
        "all": "Todas las fuentes, unos 12.000 sitios (varios minutos)",
        "scan": "Comprobar", "scanning": "Comprobando. Mantén esta página abierta.",
        "found": "Cuentas encontradas", "none": "No se encontró ninguna cuenta en los sitios que respondieron.",
        "answered": "sitios respondieron", "unanswered": "sitios no dieron una respuesta clara. Una cuenta allí no se encontraría.",
        "left_out": "sitios se omitieron porque la comprobación diaria los encontró caídos o rotos.",
        "unconfirmed": "Sin confirmar (también se encontró un nombre inventado de la misma longitud)",
        "grade": "¿La misma persona?", "site": "Sitio", "address": "Dirección",
        "refused": "Este nombre está en la lista de exclusión. Su dueño pidió que no se le busque.",
        "invalid": "Eso no es un nombre de usuario. Usa letras, cifras, punto, guion bajo y guion.",
        "responsible": "Busca tu propio nombre, o el de alguien que haya aceptado, o ten un motivo legal que puedas explicar.",
        "language": "Idioma", "error": "La comprobación falló",
    },
    "ar": {
        "title": "Helix: اعثر على الحسابات التي تحمل اسم مستخدم",
        "intro": "يفحص اسم مستخدم على مواقع كثيرة ولا يذكر إلا الحسابات التي تمكّن من تأكيدها. "
                 "كل شيء يعمل على هذا الحاسوب.",
        "username": "اسم المستخدم", "purpose": "لماذا تبحث عن هذا الاسم؟",
        "purpose_hint": "مثال: حساباتي الخاصة",
        "sources": "أين نبحث", "builtin": "56 موقعاً معروفاً (سريع)",
        "all": "كل المصادر، نحو 12,000 موقع (عدة دقائق)",
        "scan": "افحص", "scanning": "جارٍ الفحص. أبقِ هذه الصفحة مفتوحة.",
        "found": "الحسابات التي وُجدت", "none": "لم يُعثر على أي حساب في المواقع التي أجابت.",
        "answered": "موقعاً أجاب", "unanswered": "موقعاً لم يعطِ جواباً واضحاً. لن يُعثر على حساب هناك.",
        "left_out": "موقعاً استُبعد لأن الفحص اليومي وجده متوقفاً أو معطلاً.",
        "unconfirmed": "غير مؤكد (وُجد أيضاً اسم مختلق بالطول نفسه)",
        "grade": "الشخص نفسه؟", "site": "الموقع", "address": "العنوان",
        "refused": "هذا الاسم في قائمة المستثنين. طلب صاحبه ألا يُبحث عنه.",
        "invalid": "هذا ليس اسم مستخدم. استعمل الحروف والأرقام والنقطة والشرطة السفلية والشرطة.",
        "responsible": "ابحث عن اسمك، أو عن شخص وافق، أو ليكن لديك سبب قانوني تستطيع شرحه.",
        "language": "اللغة", "error": "فشل الفحص",
    },
    "pt": {
        "title": "Helix: encontre as contas de um nome de usuário",
        "intro": "Verifica um nome de usuário em muitos sites e informa apenas as contas que conseguiu confirmar. "
                 "Tudo roda neste computador.",
        "username": "Nome de usuário", "purpose": "Por que você está procurando este nome?",
        "purpose_hint": "Por exemplo: minhas próprias contas",
        "sources": "Onde procurar", "builtin": "56 sites conhecidos (rápido)",
        "all": "Todas as fontes, cerca de 12.000 sites (vários minutos)",
        "scan": "Verificar", "scanning": "Verificando. Mantenha esta página aberta.",
        "found": "Contas encontradas", "none": "Nenhuma conta encontrada nos sites que responderam.",
        "answered": "sites responderam", "unanswered": "sites não deram uma resposta clara. Uma conta lá não seria encontrada.",
        "left_out": "sites foram deixados de fora porque a verificação diária os encontrou fora do ar ou quebrados.",
        "unconfirmed": "Não confirmado (um nome inventado do mesmo tamanho também foi encontrado)",
        "grade": "A mesma pessoa?", "site": "Site", "address": "Endereço",
        "refused": "Este nome está na lista de exclusão. O dono pediu para não ser procurado.",
        "invalid": "Isso não é um nome de usuário. Use letras, números, ponto, sublinhado e hífen.",
        "responsible": "Procure o seu próprio nome, ou o de alguém que concordou, ou tenha um motivo legal que possa explicar.",
        "language": "Idioma", "error": "A verificação falhou",
    },
    "ru": {
        "title": "Helix: найдите аккаунты по имени пользователя",
        "intro": "Проверяет имя пользователя на многих сайтах и сообщает только о тех аккаунтах, которые удалось подтвердить. "
                 "Всё работает на этом компьютере.",
        "username": "Имя пользователя", "purpose": "Зачем вы ищете это имя?",
        "purpose_hint": "Например: мои собственные аккаунты",
        "sources": "Где искать", "builtin": "56 известных сайтов (быстро)",
        "all": "Все источники, около 12 000 сайтов (несколько минут)",
        "scan": "Проверить", "scanning": "Идёт проверка. Не закрывайте страницу.",
        "found": "Найденные аккаунты", "none": "На ответивших сайтах аккаунтов не найдено.",
        "answered": "сайтов ответили", "unanswered": "сайтов не дали ясного ответа. Аккаунт там не был бы найден.",
        "left_out": "сайтов пропущено: ежедневная проверка нашла их недоступными или сломанными.",
        "unconfirmed": "Не подтверждено (выдуманное имя той же длины тоже нашлось)",
        "grade": "Тот же человек?", "site": "Сайт", "address": "Адрес",
        "refused": "Это имя в списке исключённых. Его владелец просил не искать его.",
        "invalid": "Это не имя пользователя. Используйте буквы, цифры, точку, подчёркивание и дефис.",
        "responsible": "Ищите своё имя, или имя того, кто согласился, или имейте законную причину, которую можете объяснить.",
        "language": "Язык", "error": "Проверка не удалась",
    },
}


def words(lang: str) -> dict:
    """Every key in `lang`, English where the language lacks one."""
    return {**TEXT["en"], **TEXT.get(lang, {})}


def pick(accept_language: str) -> str:
    """The first language of an Accept-Language header that Helix has."""
    for part in (accept_language or "").split(","):
        code = part.split(";")[0].strip().lower()[:2]
        if code in TEXT:
            return code
    return "en"
