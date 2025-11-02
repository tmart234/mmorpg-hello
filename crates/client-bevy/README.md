# client-bevy

Minimal Bevy client app (hello world + fixed timestep), intended to render snapshots from `client-core`.

- Uses **FixedUpdate @ 20 Hz** to mirror GS cadence.
- Windows builds do **not** use Bevy dynamic linking (avoid MSVC LNK1189).
- Non-Windows can enable `dynamic_linking` for faster iteration.
