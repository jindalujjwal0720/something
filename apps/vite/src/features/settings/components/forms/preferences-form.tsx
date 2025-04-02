import { zodResolver } from '@hookform/resolvers/zod';
import { useForm } from 'react-hook-form';
import { z } from 'zod';
import {
  Form,
  FormControl,
  FormDescription,
  FormField,
  FormItem,
  FormLabel,
  FormMessage,
} from '@/components/ui/form';
import { ChevronDownIcon } from '@radix-ui/react-icons';
import { Button, buttonVariants } from '@/components/ui/button';
import { cn } from '@/utils/tw';
import { RadioGroup, RadioGroupItem } from '@/components/ui/radio-group';
import {
  supportedFonts,
  supportedThemes,
  usePreferences,
} from '@/components/ui/theme-provider';

const preferencesFormSchema = z.object({
  font: z.enum(supportedFonts),
  theme: z.enum(supportedThemes),
});

type PreferencesFormValues = z.infer<typeof preferencesFormSchema>;

const PreferencesForm = () => {
  const { preferences, setPreferences } = usePreferences();
  const form = useForm<PreferencesFormValues>({
    resolver: zodResolver(preferencesFormSchema),
    defaultValues: preferences,
  });

  const onSubmit = (data: PreferencesFormValues) => {
    setPreferences(data);
  };

  return (
    <Form {...form}>
      <form
        onSubmit={form.handleSubmit(onSubmit)}
        className="flex flex-col gap-8"
      >
        <FormField
          control={form.control}
          name="font"
          render={({ field }) => (
            <FormItem>
              <FormLabel>Font</FormLabel>
              <div className="relative w-max">
                <FormControl>
                  <select
                    className={cn(
                      buttonVariants({ variant: 'outline' }),
                      'w-[200px] appearance-none font-normal capitalize',
                    )}
                    {...field}
                  >
                    {supportedFonts.map((font) => (
                      <option key={font} value={font}>
                        {font}
                      </option>
                    ))}
                  </select>
                </FormControl>
                <ChevronDownIcon className="absolute right-3 top-2.5 h-4 w-4 opacity-50" />
              </div>
              <FormDescription>
                Set the font you want to use in the dashboard.
              </FormDescription>
              <FormMessage />
            </FormItem>
          )}
        />
        <FormField
          control={form.control}
          name="theme"
          render={({ field }) => (
            <FormItem className="flex flex-col gap-1">
              <FormLabel>Theme</FormLabel>
              <FormDescription>
                Select the theme for the dashboard.
              </FormDescription>
              <FormMessage />
              <RadioGroup
                onValueChange={field.onChange}
                defaultValue={field.value}
                className="grid max-w-md grid-cols-2 gap-8 pt-2"
              >
                <FormItem>
                  <FormLabel className="[&:has([data-state=checked])>div]:border-primary">
                    <FormControl>
                      <RadioGroupItem value="light" className="sr-only" />
                    </FormControl>
                    <ThemePreview
                      base="bg-[#ecedef]"
                      card="bg-white"
                      muted="bg-[#ecedef]"
                      accent="bg-[#ecedef]"
                    />
                    <span className="block w-full p-2 text-center font-normal">
                      Light
                    </span>
                  </FormLabel>
                </FormItem>
                <FormItem>
                  <FormLabel className="[&:has([data-state=checked])>div]:border-primary">
                    <FormControl>
                      <RadioGroupItem value="dark" className="sr-only" />
                    </FormControl>
                    <ThemePreview
                      base="bg-slate-950"
                      card="bg-slate-800"
                      muted="bg-slate-400"
                      accent="bg-slate-400"
                    />
                    <span className="block w-full p-2 text-center font-normal">
                      Dark
                    </span>
                  </FormLabel>
                </FormItem>
              </RadioGroup>
            </FormItem>
          )}
        />
        <div className="flex gap-4">
          <Button type="submit">Update preferences</Button>
        </div>
      </form>
    </Form>
  );
};

type ThemePreviewProps = {
  base: string; // Base color for the theme preview
  card: string; // Card color for the theme preview
  muted: string; // Muted color for the theme preview
  accent: string; // Accent color for the theme preview
};

const ThemePreview = ({ base, card, muted, accent }: ThemePreviewProps) => {
  return (
    <div className="items-center rounded-md p-1 border-2 border-transparent hover:border-accent">
      <div
        className={cn('flex flex-col gap-2 rounded-sm p-2 bg-[#ecedef]', base)}
      >
        <div
          className={cn(
            'flex flex-col gap-2 rounded-md p-2 shadow-sm bg-white',
            card,
          )}
        >
          <div className={cn('h-2 w-[80px] rounded-lg bg-[#ecedef]', muted)} />
          <div className={cn('h-2 w-[100px] rounded-lg bg-[#ecedef]', muted)} />
        </div>
        <div
          className={cn(
            'flex items-center gap-2 rounded-md p-2 shadow-sm bg-white',
            card,
          )}
        >
          <div className={cn('h-4 w-4 rounded-full bg-[#ecedef]', accent)} />
          <div className={cn('h-2 w-[100px] rounded-lg bg-[#ecedef]', muted)} />
        </div>
        <div
          className={cn(
            'flex items-center gap-2 rounded-md p-2 shadow-sm bg-white',
            card,
          )}
        >
          <div className={cn('h-4 w-4 rounded-full bg-[#ecedef]', accent)} />
          <div className={cn('h-2 w-[100px] rounded-lg bg-[#ecedef]', muted)} />
        </div>
      </div>
    </div>
  );
};

export default PreferencesForm;
