'use client';
import { useForm } from 'react-hook-form';
import { z } from 'zod';
import { zodResolver } from '@hookform/resolvers/zod';
import { toast } from 'sonner';
import {
  Form,
  FormControl,
  FormDescription,
  FormField,
  FormItem,
  FormLabel,
  FormMessage,
} from '@/components/ui/form';
import { Input } from '@/components/ui/input';
import { Button } from '@/components/ui/button';
import { useUpdateMeMutation } from '@/features/auth/api/auth';
import { getErrorMessage } from '@/utils/errors';
import { useAuth } from '@/features/auth/components/auth-provider';

const accountFormSchema = z.object({
  name: z.string().min(3, {
    message: 'Name must be at least 3 characters long',
  }),
  email: z.string().email().readonly(),
  imageUrl: z.string().url().or(z.literal('')).optional(),
});

type AccountFormValues = z.infer<typeof accountFormSchema>;

const AccountForm = () => {
  const { user, account } = useAuth();
  const defaultValues: AccountFormValues = {
    name: user?.name || '',
    email: account?.email || '',
    imageUrl: user?.imageUrl || '',
  };
  const form = useForm<AccountFormValues>({
    resolver: zodResolver(accountFormSchema),
    defaultValues,
  });
  const [updateMe, { isLoading }] = useUpdateMeMutation();

  const onSubmit = async (data: AccountFormValues) => {
    if (isLoading) return;
    try {
      await updateMe({
        user: {
          name: data.name,
          imageUrl: data.imageUrl,
        },
      }).unwrap();
      toast.success('Account updated successfully');
    } catch (err) {
      toast.error(getErrorMessage(err));
    }
  };

  return (
    <Form {...form}>
      <form onSubmit={form.handleSubmit(onSubmit)} className="space-y-8">
        <FormField
          control={form.control}
          name="name"
          render={({ field }) => (
            <FormItem>
              <FormLabel>Name</FormLabel>
              <FormControl>
                <Input placeholder="Your name" {...field} />
              </FormControl>
              <FormDescription>
                This is the name that will be displayed on your profile and in
                emails.
              </FormDescription>
              <FormMessage />
            </FormItem>
          )}
        />
        <FormField
          control={form.control}
          name="email"
          render={({ field }) => (
            <FormItem>
              <FormLabel>Email</FormLabel>
              <FormControl>
                <Input placeholder="Your email" disabled {...field} />
              </FormControl>
              <FormDescription>
                Your email is used to log in and send you notifications.
              </FormDescription>
              <FormMessage />
            </FormItem>
          )}
        />
        <FormField
          control={form.control}
          name="imageUrl"
          render={({ field }) => (
            <FormItem>
              <FormLabel>Profile Picture</FormLabel>
              <FormControl>
                <Input placeholder="Profile picture URL" {...field} />
              </FormControl>
              <FormDescription>
                Your profile picture helps people recognize you.
              </FormDescription>
              <FormMessage />
            </FormItem>
          )}
        />
        <Button type="submit" disabled={isLoading}>
          Update account
        </Button>
      </form>
    </Form>
  );
};

export default AccountForm;
