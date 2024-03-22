#!/usr/bin/env python3

# Copyright 2024 The gVisor Authors.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

"""Generate image with Stable Diffusion XL.

Images are written to stdout by wrapper script.
"""

import argparse
import array
import base64
import datetime
import enum
import fcntl
import io
import json
import os
import subprocess
import termios

import diffusers
import torch


# Define arguments.
class Format(enum.Enum):
  """Output format enum."""

  PNG = 'PNG'
  JPEG = 'JPEG'
  ASCII = 'ASCII'
  BRAILLE = 'BRAILLE'
  PNG_BASE64 = 'PNG-BASE64'
  METRICS = 'METRICS'

  @property
  def is_terminal_output(self):
    return self in (Format.ASCII, Format.BRAILLE, Format.METRICS)

  def __str__(self):
    return self.value


parser = argparse.ArgumentParser(
    prog='generate_image',
    description='Generate an image using Stable Diffusion XL',
)

# Arguments passed by wrapper script.
parser.add_argument('--out', required=True, type=str, help=argparse.SUPPRESS)
parser.add_argument('--terminal_pixel_width', type=str, help=argparse.SUPPRESS)
parser.add_argument('--terminal_pixel_height', type=str, help=argparse.SUPPRESS)

parser.add_argument(
    '--quiet_stderr',
    action='store_true',
    help=(
        'Suppress PyTorch messages to stderr; useful if stderr output is'
        ' captured.'
    ),
)
parser.add_argument(
    '--enable_model_cpu_offload',
    action='store_true',
    help='Offload non-main components of model to CPU if low on GPU VRAM',
)
parser.add_argument(
    '--format',
    type=Format,
    choices=list(Format),
    default=Format.BRAILLE,
    help='Output file format: ' + ', '.join(str(v) for v in Format),
)
parser.add_argument(
    '--steps', default=50, type=int, help='Number of diffusion steps'
)
parser.add_argument(
    '--noise_frac', default=0.8, type=float, help='Noise fraction'
)
parser.add_argument(
    '--enable_refiner',
    action='store_true',
    help='Use the refiner model on top of the base model for better results',
)
parser.add_argument(
    '--warm',
    action='store_true',
    help='Generate the image twice; timing metrics will measure both images',
)
parser.add_argument('prompt', type=str, help='Prompt to generate image')
args = parser.parse_args()

# Load base model.
time_start = datetime.datetime.now(datetime.timezone.utc)
base = diffusers.DiffusionPipeline.from_pretrained(
    'stabilityai/stable-diffusion-xl-base-1.0',
    torch_dtype=torch.float16,
    variant='fp16',
    use_safetensors=True,
)
if args.enable_model_cpu_offload:
  base.enable_model_cpu_offload()
else:
  base.to('cuda')
base.unet = torch.compile(base.unet, mode='reduce-overhead', fullgraph=True)

# Load refiner model if enabled.
refiner = None
if args.enable_refiner:
  refiner = diffusers.DiffusionPipeline.from_pretrained(
      'stabilityai/stable-diffusion-xl-refiner-1.0',
      text_encoder_2=base.text_encoder_2,
      vae=base.vae,
      torch_dtype=torch.float16,
      use_safetensors=True,
      variant='fp16',
  )
  if args.enable_model_cpu_offload:
    refiner.enable_model_cpu_offload()
  else:
    refiner.to('cuda')
  refiner.unet = torch.compile(
      refiner.unet, mode='reduce-overhead', fullgraph=True
  )

# Set the prompt.
default_prompt = (
    'Photorealistic image of two androids playing chess aboard a spaceship'
)
if args.format.is_terminal_output:
  # If displaying in a terminal, cartoony pictures that have sharp edges will
  # look much clearer than photorealistic pictures.
  default_prompt = 'A boring flat corporate logo that says "gVisor"'
prompt = args.prompt or default_prompt


# Generate image.
def generate_image():
  """Run the base model and maybe the refiner model to generate the image."""

  time_start_image = datetime.datetime.now(datetime.timezone.utc)
  if not args.enable_refiner:
    img = base(
        prompt=prompt,
        num_inference_steps=args.steps,
        output_type='pil',
    ).images[0]
    time_base_done = datetime.datetime.now(datetime.timezone.utc)
    time_refiner_done = None
  else:
    base_images = base(
        prompt=prompt,
        num_inference_steps=args.steps,
        denoising_end=args.noise_frac,
        output_type='latent',
    ).images
    time_base_done = datetime.datetime.now(datetime.timezone.utc)
    img = refiner(
        prompt=prompt,
        num_inference_steps=args.steps,
        denoising_start=args.noise_frac,
        image=base_images,
    ).images[0]
    time_refiner_done = datetime.datetime.now(datetime.timezone.utc)
  return img, time_start_image, time_base_done, time_refiner_done


image, cold_start_image, cold_base_done, cold_refiner_done = generate_image()
warm_start_image, warm_base_done, warm_refiner_done = None, None, None
if args.warm:
  image, warm_start_image, warm_base_done, warm_refiner_done = generate_image()


def get_optimal_terminal_width():
  """Returns the width of the terminal for ASCII image display."""
  try:
    terminal_width, terminal_height = os.get_terminal_size()
  except OSError:  # Not a TTY, return a sane default.
    return 80
  if terminal_width == 0 or terminal_height == 0:  # Incoherent terminal size.
    return 80
  if terminal_width <= 42:
    # Ridiculously small terminal, return default dimension anyway because
    # whatever we do won't look nice regardless.
    return 80
  # Try to find the aspect ratio of a single terminal character.
  terminal_pixel_width = 0
  terminal_pixel_height = 0
  if args.terminal_pixel_width.isdigit():
    terminal_pixel_width = int(args.terminal_pixel_width)
  if args.terminal_pixel_height.isdigit():
    terminal_pixel_height = int(args.terminal_pixel_height)
  if terminal_pixel_width == 0 or terminal_pixel_height == 0:
    termios_buf = array.array('H', [0, 0, 0, 0])
    fcntl.ioctl(1, termios.TIOCGWINSZ, termios_buf)
    _, _, terminal_pixel_width, terminal_pixel_height = termios_buf
  if terminal_pixel_width != 0 and terminal_pixel_height != 0:
    character_width = float(terminal_pixel_width) / float(terminal_width)
    character_height = float(terminal_pixel_height) / float(terminal_height)
    character_aspect_ratio = character_width / character_height
  else:
    character_aspect_ratio = 0.5  # Just use a sane default.
  adjusted_terminal_height = float(terminal_height) / float(
      character_aspect_ratio
  )
  image_width, image_height = image.size
  width_ratio = float(image_width) / float(terminal_width)
  height_ratio = float(image_height) / adjusted_terminal_height
  if width_ratio > height_ratio:
    # Width is determining factor.
    return terminal_width
  # Height is the determining factor.
  final_width = int(
      adjusted_terminal_height * float(image_width) / float(image_height)
  )
  # Remove one just to not make it take literally the entire console, and
  # in case our estimation for things like character size is wrong.
  final_width -= 1
  if final_width < 8:
    # Very vertical image, most likely text? So it's OK if it scrolls.
    # Return a sane default width.
    return 42
  return final_width


# Save image in desired format.
if args.format in (Format.PNG, Format.JPEG):
  image.save(args.out, args.format)
else:
  buf = io.BytesIO()
  image.save(buf, format=Format.PNG.value)
  image_bytes = buf.getvalue()
  time_done = datetime.datetime.now(datetime.timezone.utc)
  with open(args.out, 'wb') as f:
    if args.format == Format.PNG_BASE64:
      f.write(base64.standard_b64encode(image_bytes))
    elif args.format.is_terminal_output:
      image_converter_args = [
          '/usr/bin/ascii-image-converter',
          '/dev/stdin',
          '--width=%d' % (get_optimal_terminal_width(),),
      ]
      if args.format in (Format.BRAILLE, Format.METRICS):
        image_converter_args.extend(('--braille', '--dither'))
      else:
        image_converter_args.append('--complex')
      image_ascii = subprocess.run(
          image_converter_args,
          input=image_bytes,
          capture_output=True,
          check=True,
          timeout=60,
      )
      if args.format == Format.METRICS:
        split_lines = lambda x: [
            x[i : i + 1024] for i in range(0, len(x), 1024)
        ]
        results = {
            'image_ascii_base64': split_lines(
                base64.standard_b64encode(image_ascii.stdout).decode('ascii')
            ),
            'image_png_base64': split_lines(
                base64.standard_b64encode(image_bytes).decode('ascii')
            ),
        }
        for name, timestamp in (
            ('start', time_start),
            ('cold_start_image', cold_start_image),
            ('cold_base_done', cold_base_done),
            ('cold_refiner_done', cold_refiner_done),
            ('warm_start_image', warm_start_image),
            ('warm_base_done', warm_base_done),
            ('warm_refiner_done', warm_refiner_done),
            ('done', time_done),
        ):
          results[name] = (
              timestamp.isoformat() if timestamp is not None else None
          )
        # Python's `json` module always outputs strings, not bytes, so
        # we cannot directly dump to `f`. Output to string instead, then
        # encode.
        # Also, `json.dumps` doesn't add a trailing newline, so we do.
        results_json = (
            json.dumps(results, sort_keys=True, ensure_ascii=True, indent=2)
            + '\n'
        )
        f.write(results_json.encode('ascii'))
      else:
        f.write(image_ascii.stdout)
    else:
      raise ValueError(f'Unknown format: {args.format}')
