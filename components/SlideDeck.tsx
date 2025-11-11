import { useCallback, useEffect, useMemo, useState } from "react";
import styles from "./SlideDeck.module.css";

export interface Slide {
  id: string;
  title: string;
  subtitle?: string;
  theme?: "primary" | "secondary" | "tertiary";
  content: React.ReactNode;
  resources?: {
    label: string;
    url: string;
  }[];
}

interface SlideDeckProps {
  slides: Slide[];
}

const themeClass: Record<NonNullable<Slide["theme"]>, string> = {
  primary: styles.primary,
  secondary: styles.secondary,
  tertiary: styles.tertiary
};

export function SlideDeck({ slides }: SlideDeckProps) {
  const [index, setIndex] = useState(0);
  const total = slides.length;
  const slide = useMemo(() => slides[index], [slides, index]);

  const goNext = useCallback(() => {
    setIndex((current) => (current + 1) % total);
  }, [total]);

  const goPrev = useCallback(() => {
    setIndex((current) => (current - 1 + total) % total);
  }, [total]);

  useEffect(() => {
    const handler = (event: KeyboardEvent) => {
      if (event.key === "ArrowRight" || event.key === "PageDown") {
        goNext();
      }
      if (event.key === "ArrowLeft" || event.key === "PageUp") {
        goPrev();
      }
    };
    window.addEventListener("keydown", handler);
    return () => window.removeEventListener("keydown", handler);
  }, [goNext, goPrev]);

  return (
    <div className={styles.deck}>
      <div className={`${styles.slide} ${themeClass[slide.theme ?? "primary"]}`}>
        <header className={styles.header}>
          <div>
            <h1>{slide.title}</h1>
            {slide.subtitle ? <p>{slide.subtitle}</p> : null}
          </div>
          <div className={styles.controls}>
            <button onClick={goPrev} aria-label="Previous slide">
              ⟵
            </button>
            <span>
              {index + 1}/{total}
            </span>
            <button onClick={goNext} aria-label="Next slide">
              ⟶
            </button>
          </div>
        </header>
        <main className={styles.content}>{slide.content}</main>
        {slide.resources ? (
          <footer className={styles.footer}>
            <span>Resources:</span>
            <ul>
              {slide.resources.map((resource) => (
                <li key={resource.url}>
                  <a href={resource.url} target="_blank" rel="noreferrer">
                    {resource.label}
                  </a>
                </li>
              ))}
            </ul>
          </footer>
        ) : null}
      </div>
      <nav className={styles.timeline} aria-label="Slide timeline">
        {slides.map((item, idx) => (
          <button
            key={item.id}
            className={`${styles.dot} ${idx === index ? styles.activeDot : ""}`}
            onClick={() => setIndex(idx)}
            aria-label={`Go to slide ${idx + 1} - ${item.title}`}
          />
        ))}
      </nav>
    </div>
  );
}
