import { useLocalStorage } from '@/hooks/useLocalStorage';
import { createContext, useContext, useEffect } from 'react';

// eslint-disable-next-line react-refresh/only-export-components
export const supportedFonts = ['inter', 'serif', 'mono'] as const;
// eslint-disable-next-line react-refresh/only-export-components
export const supportedThemes = ['light', 'dark', 'system'] as const;

export type Preferences = {
  font: (typeof supportedFonts)[number];
  theme: (typeof supportedThemes)[number];
};

type PreferencesProviderProps = {
  children: React.ReactNode;
  defaultValue?: Preferences;
  storageKey?: string;
};

type PreferencesProviderState = {
  preferences: Preferences;
  setPreferences: (theme: Preferences) => void;
};

const initialState: PreferencesProviderState = {
  preferences: { font: 'inter', theme: 'system' },
  setPreferences: () => null,
};

const PreferencesProviderContext =
  createContext<PreferencesProviderState>(initialState);

export function ThemeProvider({
  children,
  defaultValue: defaultTheme = { font: 'inter', theme: 'light' },
  storageKey = 'something-ui-theme',
  ...props
}: PreferencesProviderProps) {
  const [preferences, setPreferences] = useLocalStorage<Preferences>(
    storageKey,
    defaultTheme,
  );

  useEffect(() => {
    const root = window.document.documentElement;

    root.classList.remove(...supportedThemes, ...supportedFonts);

    if (preferences.theme === 'system') {
      const systemTheme = window.matchMedia('(prefers-color-scheme: dark)')
        .matches
        ? 'dark'
        : 'light';

      root.classList.add(systemTheme);
      return;
    }

    root.classList.add(preferences.font);
    root.classList.add(preferences.theme);
  }, [preferences]);

  const value = {
    preferences,
    setPreferences,
  };

  return (
    <PreferencesProviderContext.Provider {...props} value={value}>
      {children}
    </PreferencesProviderContext.Provider>
  );
}

// eslint-disable-next-line react-refresh/only-export-components
export const usePreferences = () => {
  const context = useContext(PreferencesProviderContext);

  if (context === undefined)
    throw new Error('useTheme must be used within a ThemeProvider');

  return context;
};
