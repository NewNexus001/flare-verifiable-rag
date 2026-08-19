import { getRequestConfig } from "next-intl/server";

export const locales = ["en", "es", "zh", "ja", "ar"] as const;
export type Locale = (typeof locales)[number];
export const defaultLocale: Locale = "en";

export default getRequestConfig(async ({ requestLocale }) => {
  // requestLocale is a Promise<string | undefined> — await the segment value
  const segment = await requestLocale;
  const validLocale = locales.includes(segment as Locale)
    ? (segment as Locale)
    : defaultLocale;

  return {
    locale: validLocale,
    messages: (await import(`./messages/${validLocale}.json`)).default,
  };
});
