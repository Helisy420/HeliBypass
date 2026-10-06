//! Rasterises the HeliBypass mark (exported from the Figma file as a 106x106 vector) into
//! RGBA pixels, for the tray icon, the window icon and the `.ico` embedded in the executable.
//! Dependency-free on purpose: `build.rs` includes this file too.

type Rgba = [f32; 4];

fn hex(c: u32, a: f32) -> Rgba {
    [((c >> 16) & 255) as f32 / 255.0, ((c >> 8) & 255) as f32 / 255.0, (c & 255) as f32 / 255.0, a]
}

enum Shape {
    Capsule { a: (f32, f32), b: (f32, f32), r: f32 },
    Circle { c: (f32, f32), r: f32 },
    RoundRect { x0: f32, y0: f32, x1: f32, y1: f32, r: f32 },
}

impl Shape {
    fn contains(&self, p: (f32, f32)) -> bool {
        match *self {
            Shape::Circle { c, r } => (p.0 - c.0).powi(2) + (p.1 - c.1).powi(2) <= r * r,
            Shape::Capsule { a, b, r } => {
                let (dx, dy) = (b.0 - a.0, b.1 - a.1);
                let len2 = dx * dx + dy * dy;
                let t = if len2 == 0.0 { 0.0 } else { (((p.0 - a.0) * dx + (p.1 - a.1) * dy) / len2).clamp(0.0, 1.0) };
                let (cx, cy) = (a.0 + t * dx, a.1 + t * dy);
                (p.0 - cx).powi(2) + (p.1 - cy).powi(2) <= r * r
            }
            Shape::RoundRect { x0, y0, x1, y1, r } => {
                let (cx, cy) = (p.0.clamp(x0 + r, x1 - r), p.1.clamp(y0 + r, y1 - r));
                p.0 >= x0 && p.0 <= x1 && p.1 >= y0 && p.1 <= y1 && (p.0 - cx).powi(2) + (p.1 - cy).powi(2) <= r * r
            }
        }
    }
}

struct Palette {
    accent: Rgba,
    accent_dark: Rgba,
    amber: Rgba,
    surface: Rgba,
    tile: Rgba,
    tile_border: Rgba,
}

fn palette(active: bool) -> Palette {
    if active {
        Palette {
            accent: hex(0x7589DB, 1.0),
            accent_dark: hex(0x5368C6, 1.0),
            amber: hex(0xF0B45C, 1.0),
            surface: hex(0x121830, 1.0),
            tile: hex(0x0B0F1E, 1.0),
            tile_border: hex(0x242D52, 1.0),
        }
    } else {
        Palette {
            accent: hex(0x6B7699, 1.0),
            accent_dark: hex(0x4A5278, 1.0),
            amber: hex(0x8A7550, 1.0),
            surface: hex(0x121830, 1.0),
            tile: hex(0x0B0F1E, 1.0),
            tile_border: hex(0x242D52, 1.0),
        }
    }
}

/// The mark in its 106x106 design space, back to front.
fn mark(p: &Palette) -> Vec<(Shape, Rgba)> {
    const W: f32 = 3.7 / 2.0;
    let (l, r) = (20.8214, 85.1786);
    let mut v: Vec<(Shape, Rgba)> = Vec::new();
    // rails
    for x in [l, r] {
        v.push((Shape::Capsule { a: (x, 15.1429), b: (x, 90.8571), r: W }, p.accent));
    }
    // crossbar stubs
    v.push((Shape::Capsule { a: (l, 60.5714), b: (40.6964, 60.5714), r: W }, p.accent_dark));
    v.push((Shape::Capsule { a: (65.3036, 60.5714), b: (r, 60.5714), r: W }, p.accent_dark));
    // centre stub
    v.push((Shape::RoundRect { x0: 49.7821, y0: 47.3214, x1: 56.2179, y1: 73.8214, r: 3.2 }, p.accent_dark));
    // arch: cubic (l,60.57) (l,18.93) (r,18.93) (r,60.57) as a chain of capsules
    let bez = |t: f32| {
        let u = 1.0 - t;
        let (p0, p1, p2, p3) = ((l, 60.5714), (l, 18.9286), (r, 18.9286), (r, 60.5714));
        (
            u * u * u * p0.0 + 3.0 * u * u * t * p1.0 + 3.0 * u * t * t * p2.0 + t * t * t * p3.0,
            u * u * u * p0.1 + 3.0 * u * u * t * p1.1 + 3.0 * u * t * t * p2.1 + t * t * t * p3.1,
        )
    };
    for i in 0..40 {
        v.push((Shape::Capsule { a: bez(i as f32 / 40.0), b: bez((i + 1) as f32 / 40.0), r: W }, p.accent));
    }
    // end dots and rail nodes
    for (x, y) in [(l, 15.1429), (r, 15.1429), (l, 90.8571), (r, 90.8571)] {
        v.push((Shape::Circle { c: (x, y), r: 8.33 }, p.accent));
    }
    for x in [l, r] {
        v.push((Shape::Circle { c: (x, 60.5714), r: 6.06 }, p.accent));
    }
    // amber ring at the apex
    v.push((Shape::Circle { c: (53.0, 29.3393), r: 12.49 }, p.amber));
    v.push((Shape::Circle { c: (53.0, 29.3393), r: 4.35 }, p.surface));
    v
}

/// Render a `size`x`size` icon as straight-alpha RGBA8. `tile` draws the dark rounded app tile
/// behind the mark; `active` selects full colour (true) or the muted "off" palette.
pub fn render(size: u32, tile: bool, active: bool) -> Vec<u8> {
    let pal = palette(active);
    let shapes = mark(&pal);
    let s = size as f32;
    // the mark fills 70% of a tile, or 94% of the canvas without one
    let scale = if tile { s * 0.70 / 106.0 } else { s * 0.94 / 106.0 };
    let off = (s - 106.0 * scale) / 2.0;
    const SS: u32 = 4;
    let radius = s * 0.24;
    let tile_shape = Shape::RoundRect { x0: 0.5, y0: 0.5, x1: s - 0.5, y1: s - 0.5, r: radius };
    let tile_inner = Shape::RoundRect { x0: 1.5, y0: 1.5, x1: s - 1.5, y1: s - 1.5, r: radius - 1.0 };

    let mut out = vec![0u8; (size * size * 4) as usize];
    for y in 0..size {
        for x in 0..size {
            let mut acc = [0.0f32; 4]; // premultiplied
            for sy in 0..SS {
                for sx in 0..SS {
                    let p = (x as f32 + (sx as f32 + 0.5) / SS as f32, y as f32 + (sy as f32 + 0.5) / SS as f32);
                    let mut px: Rgba = [0.0; 4];
                    let mut over = |c: Rgba| {
                        let a = c[3];
                        px = [c[0] * a + px[0] * (1.0 - a), c[1] * a + px[1] * (1.0 - a), c[2] * a + px[2] * (1.0 - a), a + px[3] * (1.0 - a)];
                    };
                    if tile {
                        if tile_shape.contains(p) {
                            over(if tile_inner.contains(p) { pal.tile } else { pal.tile_border });
                        }
                    }
                    let q = ((p.0 - off) / scale, (p.1 - off) / scale);
                    for (shape, color) in &shapes {
                        if shape.contains(q) {
                            over(*color);
                        }
                    }
                    for i in 0..4 {
                        acc[i] += px[i];
                    }
                }
            }
            let n = (SS * SS) as f32;
            let a = acc[3] / n;
            let i = ((y * size + x) * 4) as usize;
            if a > 0.0 {
                for c in 0..3 {
                    out[i + c] = ((acc[c] / n / a).clamp(0.0, 1.0) * 255.0 + 0.5) as u8;
                }
            }
            out[i + 3] = (a * 255.0 + 0.5) as u8;
        }
    }
    out
}

/// A multi-resolution `.ico` (uncompressed 32-bit DIB entries; accepted by every Windows version).
pub fn ico_bytes(sizes: &[u32]) -> Vec<u8> {
    let images: Vec<(u32, Vec<u8>)> = sizes
        .iter()
        .map(|&sz| {
            let rgba = render(sz, true, true);
            let mut dib = Vec::new();
            dib.extend_from_slice(&40u32.to_le_bytes());
            dib.extend_from_slice(&(sz as i32).to_le_bytes());
            dib.extend_from_slice(&((sz * 2) as i32).to_le_bytes()); // XOR + AND masks
            dib.extend_from_slice(&1u16.to_le_bytes());
            dib.extend_from_slice(&32u16.to_le_bytes());
            dib.extend_from_slice(&[0u8; 24]);
            for y in (0..sz).rev() {
                for x in 0..sz {
                    let i = ((y * sz + x) * 4) as usize;
                    dib.extend_from_slice(&[rgba[i + 2], rgba[i + 1], rgba[i], rgba[i + 3]]);
                }
            }
            let mask_row = (sz.div_ceil(32) * 4) as usize;
            dib.extend(std::iter::repeat_n(0u8, mask_row * sz as usize));
            (sz, dib)
        })
        .collect();

    let mut out = Vec::new();
    out.extend_from_slice(&[0, 0, 1, 0]);
    out.extend_from_slice(&(images.len() as u16).to_le_bytes());
    let mut offset = 6 + 16 * images.len() as u32;
    for (sz, dib) in &images {
        out.push(if *sz >= 256 { 0 } else { *sz as u8 });
        out.push(if *sz >= 256 { 0 } else { *sz as u8 });
        out.extend_from_slice(&[0, 0]);
        out.extend_from_slice(&1u16.to_le_bytes());
        out.extend_from_slice(&32u16.to_le_bytes());
        out.extend_from_slice(&(dib.len() as u32).to_le_bytes());
        out.extend_from_slice(&offset.to_le_bytes());
        offset += dib.len() as u32;
    }
    for (_, dib) in images {
        out.extend_from_slice(&dib);
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn renders_mark_with_alpha_and_amber_ring() {
        let px = render(64, false, true);
        assert_eq!(px.len(), 64 * 64 * 4);
        // corner is transparent, the rail end dot is opaque accent blue
        assert_eq!(px[3], 0);
        let at = |x: usize, y: usize| &px[(y * 64 + x) * 4..(y * 64 + x) * 4 + 4];
        let dot = at((20.8214 / 106.0 * 64.0 * 0.94 + 64.0 * 0.03) as usize, (15.14 / 106.0 * 64.0 * 0.94 + 64.0 * 0.03) as usize);
        assert!(dot[3] > 240 && dot[2] > dot[0], "{dot:?}");
        // amber ring: red channel dominates somewhere near the apex
        let ring = at(32, (29.34 / 106.0 * 64.0 * 0.94 + 64.0 * 0.03) as usize - 6);
        assert!(ring[0] > 200 && ring[1] > 140 && ring[2] < 130, "{ring:?}");
    }

    #[test]
    fn ico_has_valid_directory() {
        let ico = ico_bytes(&[16, 32, 48, 256]);
        assert_eq!(&ico[..6], &[0, 0, 1, 0, 4, 0]);
        // directory entry 0: 16x16, 32 bpp, and its data offset is inside the file
        assert_eq!((ico[6], ico[7]), (16, 16));
        let off = u32::from_le_bytes(ico[6 + 12..6 + 16].try_into().unwrap()) as usize;
        assert!(off < ico.len());
        assert_eq!(u32::from_le_bytes(ico[off..off + 4].try_into().unwrap()), 40);
    }
}
