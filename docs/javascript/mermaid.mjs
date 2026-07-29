import mermaid from 'https://cdn.jsdelivr.net/npm/mermaid@11.12.2/dist/mermaid.esm.mjs';
import elkLayouts from 'https://cdn.jsdelivr.net/npm/@mermaid-js/layout-elk@0/dist/mermaid-layout-elk.esm.min.mjs';

mermaid.registerIconPacks([
  {
    name: 'fa',
    loader: () => {
      return fetch('https://unpkg.com/@iconify-json/fa6-solid@1/icons.json')
        .then((res) => {
          return res.json();
        });
    },
  },
  {
    name: 'fab',
    loader: () => {
      return fetch('https://unpkg.com/@iconify-json/fa6-brands@1/icons.json')
        .then((res) => {
          return res.json();
        });
    },
  },
  {
    name: 'logos',
    loader: () => {
      return fetch('https://unpkg.com/@iconify-json/logos@1/icons.json')
        .then((res) => {
          return res.json();
        });
    },
  },
]);


mermaid.registerLayoutLoaders(elkLayouts);
mermaid.initialize({
  startOnLoad: true,
  layout: "elk",
  theme: 'base'
});

window.mermaid = mermaid;
