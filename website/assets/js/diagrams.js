// Copyright 2026 The gVisor Authors.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

// SVG animations keep running offscreen unless paused.
(() => {
  const diagrams = document.querySelectorAll('.diagram-frame > svg');
  const motion = matchMedia('(prefers-reduced-motion: reduce)');
  const observer = new IntersectionObserver((entries) => {
    for (const entry of entries) {
      if (entry.isIntersecting && !motion.matches) {
        entry.target.unpauseAnimations();
      } else {
        entry.target.pauseAnimations();
      }
    }
  });

  function observeDiagrams() {
    observer.disconnect();
    for (const svg of diagrams) {
      svg.pauseAnimations();
      if (!motion.matches) observer.observe(svg);
    }
  }

  motion.addEventListener('change', observeDiagrams);
  observeDiagrams();
})();
