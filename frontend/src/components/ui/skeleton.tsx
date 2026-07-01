import { cn } from "@/lib/utils";

// Content-shaped loading placeholder. Decorative (aria-hidden): the loading
// state is announced separately via aria-busy on the container.
export function Skeleton({ className, ...props }: React.HTMLAttributes<HTMLDivElement>) {
  return (
    <div
      aria-hidden
      className={cn("animate-pulse rounded-md bg-muted", className)}
      {...props}
    />
  );
}
