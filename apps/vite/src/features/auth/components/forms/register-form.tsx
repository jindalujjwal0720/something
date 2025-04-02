import {
  Card,
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle,
} from '@/components/ui/card';
import { zodResolver } from '@hookform/resolvers/zod';
import { useForm } from 'react-hook-form';
import { z } from 'zod';
import {
  Form,
  FormControl,
  FormField,
  FormItem,
  FormLabel,
  FormMessage,
} from '@/components/ui/form';
import { Input } from '@/components/ui/input';
import { Button } from '@/components/ui/button';
import { Link } from 'react-router-dom';
import { useRegisterMutation } from '../../api/auth';
import { toast } from 'sonner';
import { getErrorMessage } from '@/utils/errors';
import { RegisterResponse } from '../../types/api/auth';

const registerFormSchema = z
  .object({
    name: z.string().min(3, {
      message: 'Name must be at least 3 characters long',
    }),
    email: z.string().email(),
    password: z
      .string()
      .min(8)
      .regex(
        /^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]{8,}$/,
        {
          message:
            'Password must contain at least 8 characters, one uppercase, one lowercase, one number and one special character (@$!%*?&)',
        },
      ),
    confirmPassword: z.string(),
  })
  .refine((data) => data.password === data.confirmPassword, {
    message: 'Passwords do not match',
    path: ['confirmPassword'],
  });

type RegisterFormValues = z.infer<typeof registerFormSchema>;

interface RegisterFormProps {
  onSuccess?: (data: RegisterResponse) => void;
}

const RegisterForm = ({ onSuccess }: RegisterFormProps) => {
  const form = useForm<RegisterFormValues>({
    resolver: zodResolver(registerFormSchema),
    defaultValues: {
      name: '',
      email: '',
      password: '',
      confirmPassword: '',
    },
  });
  const [registerUser, { isLoading }] = useRegisterMutation();

  const onSubmit = async (data: RegisterFormValues) => {
    try {
      const payload = await registerUser({
        user: {
          name: data.name,
          imageUrl: undefined,
        },
        account: { email: data.email, password: data.password },
      }).unwrap();
      if (onSuccess instanceof Function) {
        onSuccess(payload);
      }
    } catch (err) {
      toast.error(getErrorMessage(err));
    }
  };

  return (
    <Card className="w-full max-w-sm lg:max-w-2xl">
      <CardHeader>
        <CardTitle className="text-2xl">Create an account</CardTitle>
        <CardDescription>
          Enter your name, email and password to create an account.
        </CardDescription>
      </CardHeader>
      <CardContent>
        <Form {...form}>
          <form
            onSubmit={form.handleSubmit(onSubmit)}
            className="flex flex-col gap-4 lg:grid lg:grid-cols-2 lg:gap-6"
          >
            <FormField
              control={form.control}
              name="name"
              render={({ field }) => (
                <FormItem>
                  <FormLabel>Name</FormLabel>
                  <FormControl>
                    <Input placeholder="Your name" {...field} />
                  </FormControl>
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
                    <Input placeholder="Your email" {...field} />
                  </FormControl>
                  <FormMessage />
                </FormItem>
              )}
            />
            <FormField
              control={form.control}
              name="password"
              render={({ field }) => (
                <FormItem>
                  <FormLabel>Password</FormLabel>
                  <FormControl>
                    <Input
                      type="password"
                      placeholder="Your password"
                      {...field}
                    />
                  </FormControl>
                  <FormMessage />
                </FormItem>
              )}
            />
            <FormField
              control={form.control}
              name="confirmPassword"
              render={({ field }) => (
                <FormItem>
                  <FormLabel>Confirm Password</FormLabel>
                  <FormControl>
                    <Input
                      type="password"
                      placeholder="Confirm your password"
                      {...field}
                    />
                  </FormControl>
                  <FormMessage />
                </FormItem>
              )}
            />
            <Button
              type="submit"
              className="w-full lg:col-span-2"
              disabled={isLoading}
            >
              {isLoading ? 'Loading...' : 'Register'}
            </Button>
          </form>
        </Form>
        <div className="mt-4 text-center text-sm">
          Already have an account?{' '}
          <Link to="/auth/login" className="underline">
            Log in
          </Link>
        </div>
      </CardContent>
    </Card>
  );
};

export default RegisterForm;
