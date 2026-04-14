import { useEffect, useRef } from "react";

export function useDebouncedEffect(effect, deps, delay) {
  const callback = useRef(effect);
  callback.current = effect;

  useEffect(() => {
    const timer = setTimeout(() => {
      callback.current();
    }, delay);
    return () => clearTimeout(timer);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [...deps, delay]);
}

