import {
  Card,
  CardHeader,
  CardTitle,
  CardDescription,
  CardContent,
} from '@/components/ui/card';
import {
  Terminal,
  Database,
  Puzzle,
  Zap,
  CheckCircle2,
  TestTube2,
  BookMarked,
  Cog,
  FileCode,
  ShieldCheck,
  ShieldBan,
} from 'lucide-react';
import Navbar from '@/features/navbar/components/navbar';
import { cn } from '@/utils/tw';

export default function Component() {
  return (
    <div className="min-h-screen flex flex-col bg-gradient-to-b from-background to-secondary">
      <Navbar variant="fixed" />
      <main className="flex-grow container mx-auto px-4 sm:px-6 lg:px-8 py-12 mt-8">
        <div className="text-center mb-12 flex flex-col gap-4">
          <h2 className="!leading-snug text-4xl sm:text-5xl md:text-6xl font-extrabold bg-gradient-to-b from-muted-foreground to-primary text-transparent bg-clip-text">
            Something Starter Template
          </h2>
          <p className="text-xl text-muted-foreground">
            A powerful, feature-rich starter template for modern web
            applications
          </p>
        </div>

        <div
          className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4 md:gap-8"
          id="features"
        >
          <FeatureCard
            icon={<ShieldCheck className="h-8 w-8 text-blue-500" />}
            title="Advanced Authentication"
            description="Secure multi-factor auth with authenticator app, otp, recovery email, and codes"
            features={[
              'Basic email and password auth',
              'Password reset using email otp',
              'Change password using previous password',
              'Two-factor authentication',
              'Authenticator app setup',
              'Secure OTP via email',
              'Account recovery email',
              'Account recovery backup codes',
              'Anamolous login detection',
            ]}
            className="row-span-2"
          />
          <FeatureCard
            icon={<Zap className="h-8 w-8 text-red-500" />}
            title="Event-Driven Architecture"
            description="Scalable and responsive applications with event-driven design"
            features={['Node.js Event Emitter with Pub/Sub pattern']}
          />
          <FeatureCard
            icon={<Puzzle className="h-8 w-8 text-indigo-500" />}
            title="Modular Repositories"
            description="Clean and maintainable code structure with modular repositories"
            features={['Bulletproof Node.js and React architecture']}
          />
          <div className="col-span-2 hidden lg:grid lg:grid-cols-3 gap-8">
            <FeatureCard
              icon={<Terminal className="h-8 w-8 text-purple-500" />}
              title="Vite & Node.js"
              description="Lightning-fast build times with Vite and robust backend"
            />
            <FeatureCard
              icon={<Database className="h-8 w-8 text-green-500" />}
              title="MongoDB & Mongoose"
              description="Flexible database modeling using Mongoose"
            />
            <FeatureCard
              icon={<TestTube2 className="h-8 w-8 text-yellow-500" />}
              title="Testing with Jest"
              description="Comprehensive test suite with Jest for backend and frontend"
            />
          </div>
          <FeatureCard
            icon={<ShieldBan className="h-8 w-8 text-amber-500" />}
            title="Role-Based Access Control"
            description="Fine-grained access control with roles and permissions"
            className="md:col-span-2 lg:col-span-1"
          />
          <div className="col-span-2 hidden lg:grid lg:grid-cols-3 gap-8">
            <FeatureCard
              icon={<BookMarked className="h-8 w-8 text-pink-500" />}
              title="Storybook"
              description="Storybook for testing UI components"
            />
            <FeatureCard
              icon={<Cog className="h-8 w-8 text-gray-500" />}
              title="Full TypeScript Support"
              description="Type-safe codebase with TypeScript"
            />
            <FeatureCard
              icon={<FileCode className="h-8 w-8 text-cyan-500" />}
              title="Linting & Formatting"
              description="Consistent code style with ESLint and Prettier"
            />
          </div>
          <div className="md:col-span-2 lg:hidden grid grid-cols-2 gap-4 md:gap-8">
            <FeatureCard
              icon={<Terminal className="h-8 w-8 text-purple-500" />}
              title="Vite & Node.js"
              description="Lightning-fast build times with Vite and robust backend"
            />
            <FeatureCard
              icon={<Database className="h-8 w-8 text-green-500" />}
              title="MongoDB & Mongoose"
              description="Flexible database modeling using Mongoose"
            />
            <FeatureCard
              icon={<TestTube2 className="h-8 w-8 text-yellow-500" />}
              title="Testing with Jest"
              description="Comprehensive test suite with Jest for backend and frontend"
            />
            <FeatureCard
              icon={<BookMarked className="h-8 w-8 text-pink-500" />}
              title="Storybook"
              description="Storybook for testing UI components"
            />
            <FeatureCard
              icon={<Cog className="h-8 w-8 text-gray-500" />}
              title="Full TypeScript Support"
              description="Type-safe codebase with TypeScript"
            />
            <FeatureCard
              icon={<FileCode className="h-8 w-8 text-cyan-500" />}
              title="Linting & Formatting"
              description="Consistent code style with ESLint and Prettier"
            />
          </div>
        </div>
      </main>

      <footer className="bg-muted p-4 sm:px-6 lg:px-8 border-t">
        <div className="container mx-auto text-center text-muted-foreground">
          <p>
            &copy; {new Date().getFullYear()} Something. All rights reserved.
          </p>
        </div>
      </footer>
    </div>
  );
}

interface FeatureCardProps {
  icon: React.ReactNode;
  title: string;
  description?: string;
  features?: string[];
  className?: string;
}

function FeatureCard({
  icon,
  title,
  description,
  features = [],
  className,
}: FeatureCardProps) {
  return (
    <Card className={cn('hover:shadow-lg', className)}>
      <CardHeader className={features.length > 0 ? 'mb-0' : 'mb-6'}>
        <div className="text-primary mb-4">{icon}</div>
        <CardTitle>{title}</CardTitle>
        {description && <CardDescription>{description}</CardDescription>}
      </CardHeader>
      {features.length > 0 && (
        <CardContent>
          <ul className="space-y-2 text-muted-foreground">
            {features.map((feature, index) => (
              <li key={index} className="flex text-sm">
                <CheckCircle2 className="size-4 shrink-0 mt-0.5 text-green-500 mr-2" />
                {feature}
              </li>
            ))}
          </ul>
        </CardContent>
      )}
    </Card>
  );
}
