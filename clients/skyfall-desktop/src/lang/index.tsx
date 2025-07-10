import { createInstance } from "i18next";
import { I18nextProvider } from "react-i18next";

// Import language files
import * as LANG_EN from "./en.json";
import { ReactNode } from "react";

const i18n = createInstance({
    fallbackLng: "en",
    debug: true,
    interpolation: {
        escapeValue: false
    },
    resources: {
        en: {
            translation: LANG_EN
        }
    }
});

i18n.init();

export function LocalizationProvider({children}: {children?: ReactNode | ReactNode[]}) {
    return <I18nextProvider i18n={i18n} defaultNS="translation">
        {children}
    </I18nextProvider>
}
