# YouTube Video Overlay with FFmpeg

This application intercepts YouTube video streams and adds custom overlay text directly onto the video frames using FFmpeg.

## How It Works

1. **Interception**: The MITM proxy intercepts all HTTP/HTTPS traffic using NetFilterSDK
2. **Detection**: Identifies YouTube video streams by:
   - URL patterns (googlevideo.com, youtube.com, ytimg.com)
   - Content-Type headers (video/mp4, video/webm, etc.)
3. **Processing**: For each video segment:
   - Extracts video data from the network stream
   - Writes to temporary file
   - Processes with FFmpeg to add overlay text
   - Reads processed video back
   - Replaces original stream content
4. **Delivery**: Sends modified video back to browser

## Requirements

- **FFmpeg**: Must be installed and accessible
  - Download from: https://ffmpeg.org/download.html
  - Ensure `ffmpeg.exe` is in PATH or set `FFMPEG_PATH` environment variable

## Configuration

### Overlay Text

Set the overlay text via:
1. Command line argument:
   ```bash
   VideoStreamModifier.exe "Your Custom Text"
   ```

2. Environment variable:
   ```bash
   set VIDEO_OVERLAY_TEXT=Your Custom Text
   VideoStreamModifier.exe
   ```

3. Default: "Custom Overlay" (if not specified)

### FFmpeg Path

If FFmpeg is not in PATH, set:
```bash
set FFMPEG_PATH=C:\path\to\ffmpeg.exe
```

## Building

1. Open `VideoStreamModifier.sln` in Visual Studio
2. Build for x64 Release configuration
3. Ensure all DLLs are in the output directory:
   - `nfapi.dll`
   - `protocolfilters.dll`
   - `libcrypto-3-x64.dll`
   - `libssl-3-x64.dll`

## Usage

1. **Run as Administrator**: Required for network interception
   ```bash
   VideoStreamModifier.exe "Watch This!"
   ```

2. **Open Browser**: Navigate to any YouTube video

3. **Watch**: The overlay text will appear on the video frames

## Technical Details

### Video Processing

- Each video segment is processed independently
- Uses fragmented MP4 format for streaming compatibility
- FFmpeg command:
  ```
  ffmpeg -i input.mp4 
    -vf "drawtext=text='Your Text':fontcolor=white:fontsize=24:x=10:y=10:box=1:boxcolor=black@0.5" 
    -c:v libx264 -preset ultrafast -crf 23 -tune zerolatency 
    -c:a copy 
    -movflags frag_keyframe+empty_moov+faststart 
    -f mp4 output.mp4
  ```

### Performance Considerations

- Processing happens in real-time, which may cause:
  - Slight delay in video playback
  - Higher CPU usage
  - Temporary files created during processing

### Limitations

- Only processes video segments > 10KB (small chunks are passed through)
- Processing time depends on segment size and FFmpeg performance
- May not work with all video formats (optimized for MP4)
- Live streams may have noticeable delay

## Troubleshooting

### Video Not Processing

1. Check console output for error messages
2. Verify FFmpeg is accessible: `ffmpeg -version`
3. Check that video segments are being detected (look for "Processing YouTube video segment" messages)
4. Ensure you're accessing YouTube videos (googlevideo.com URLs)

### FFmpeg Errors

- Check FFmpeg installation
- Verify write permissions for temp directory
- Check available disk space

### Performance Issues

- Reduce overlay text complexity
- Use faster FFmpeg presets (already using `ultrafast`)
- Consider processing only specific video qualities

## Customization

### Overlay Appearance

Edit the FFmpeg drawtext filter in `processVideoWithFFmpeg()`:
- `fontsize`: Text size
- `x`, `y`: Position
- `fontcolor`: Text color
- `boxcolor`: Background box color
- `boxborderw`: Border width

### Video Quality

Adjust encoding parameters:
- `crf`: Quality (lower = better, 18-28 range)
- `preset`: Speed vs quality (ultrafast, fast, medium, slow)

## Notes

- This is a proof-of-concept implementation
- For production use, consider:
  - Caching processed segments
  - Async processing
  - Better error handling
  - Support for more video formats

