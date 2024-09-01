export const convertDurationToReadable = (
  durationInSeconds: number,
): string => {
  const seconds = Math.floor(durationInSeconds);
  const minutes = Math.floor(seconds / 60);
  const hours = Math.floor(minutes / 60);
  const days = Math.floor(hours / 24);

  if (days > 0) return `${days}:${hours % 24} days`;
  if (hours > 0) return `${hours}:${minutes % 60} hours`;
  if (minutes > 0) return `${minutes}:${seconds % 60} minutes`;
  return `${seconds} seconds`;
};
