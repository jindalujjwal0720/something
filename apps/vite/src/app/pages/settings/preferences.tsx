import PreferencesForm from '@/features/settings/components/forms/preferences-form';

const Preferences = () => {
  return (
    <div className="space-y-6">
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

export default Preferences;
