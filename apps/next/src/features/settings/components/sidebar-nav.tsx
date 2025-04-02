'use client';
import { buttonVariants } from '@/components/ui/button';
import { cn } from '@/utils/tw';
import Link from 'next/link';
import { usePathname } from 'next/navigation';

interface NavItem {
  href: string;
  title: string;
}

interface SidebarNavProps extends React.HTMLAttributes<HTMLElement> {
  items: NavItem[];
}

const SidebarNav = ({ items, className, ...props }: SidebarNavProps) => {
  const pathname = usePathname();

  const activeNavItem = items
    .filter((i) => pathname.startsWith(i.href))
    .sort((a, b) => b.href.length - a.href.length)[0];

  return (
    <nav
      className={cn('flex gap-2 lg:flex-col lg:gap-1', className)}
      {...props}
    >
      {items.map((item) => (
        <Link
          key={item.href}
          href={item.href}
          className={cn(
            buttonVariants({ variant: 'ghost' }),
            activeNavItem.href === item.href ? 'bg-muted hover:bg-muted' : '',
            'justify-start',
          )}
        >
          {item.title}
        </Link>
      ))}
    </nav>
  );
};

export default SidebarNav;
