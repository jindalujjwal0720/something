import { useCallback, useEffect, useState } from 'react';

const useTimer = (seconds: number) => {
  const [timer, setTimer] = useState<number>(0); // in seconds

  useEffect(() => {
    if (timer > 0) {
      const interval = setInterval(() => {
        setTimer((prev) => prev - 1);
      }, 1000);

      return () => clearInterval(interval);
    }
  }, [timer]);

  useEffect(() => {
    setTimer(seconds);
  }, [seconds]);

  const resetTimer = useCallback((seconds: number) => {
    setTimer(Math.floor(seconds));
  }, []);

  return [timer, resetTimer] as const;
};

export default useTimer;
