import PreferencesForm from '@/features/settings/components/forms/preferences-form';

const PreferencesPage = () => {
  return (
    <div className="flex flex-col gap-6">
      <div>
        <h3 className="text-lg font-medium">Preferences</h3>
        <p className="text-sm text-muted-foreground">
          Customize the appearance of the app. Automatically switch between
          different themes.
        </p>
      </div>
      <PreferencesForm />
    </div>
  );
};

export default PreferencesPage;
