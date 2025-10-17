import express from 'express';
import cors from 'cors';
import crypto from 'crypto';

const app = express();

// Enable CORS for n8n
app.use(cors());
app.use(express.json({ limit: '50mb' }));
  app.use(express.urlencoded({ limit: '50mb', extended: true }));

// Health check endpoint
app.get('/', (req, res) => {
  res.json({
    status: 'ok',
    service: 'Aliyun OSS Signature API',
    version: '1.0.0'
  });
});

// Generate OSS signature
app.post('/oss/sign', (req, res) => {
  try {
    const { fileName, content, contentType = 'text/plain' } = req.body;

    // Validate input
    if (!fileName) {
      return res.status(400).json({ error: 'fileName is required' });
    }

    if (!content) {
      return res.status(400).json({ error: 'content is required' });
    }

    // Get credentials from environment
    const accessKeyId = process.env.ALIYUN_ACCESS_KEY_ID;
    const accessKeySecret = process.env.ALIYUN_ACCESS_KEY_SECRET;
    const bucket = process.env.ALIYUN_BUCKET;
    const region = process.env.ALIYUN_OSS_REGION || 'oss-cn-shanghai';

    if (!accessKeyId || !accessKeySecret || !bucket) {
      return res.status(500).json({
        error: 'Server configuration error: missing Aliyun credentials'
      });
    }

    // Calculate MD5
    const contentMD5 = crypto.createHash('md5')
      .update(content)
      .digest('base64');

    const date = new Date().toUTCString();

    // Create OSS signature
    const stringToSign = `PUT\n${contentMD5}\n${contentType}\n${date}\n/${bucket}/${fileName}`;
    const signature = crypto.createHmac('sha1', accessKeySecret)
      .update(stringToSign)
      .digest('base64');

    const authorization = `OSS ${accessKeyId}:${signature}`;
    const url = `https://${bucket}.${region}.aliyuncs.com/${fileName}`;

    // Return signature data
    res.json({
      success: true,
      url,
      headers: {
        'Authorization': authorization,
        'Date': date,
        'Content-Type': contentType,
        'Content-MD5': contentMD5
      },
      fileName,
      bucket
    });

  } catch (error) {
    console.error('Error generating signature:', error);
    res.status(500).json({
      error: 'Failed to generate signature',
      message: error.message
    });
  }
});

// Upload with public access option
app.post('/oss/upload', async (req, res) => {
  try {
    const { fileName, content, contentType = 'text/plain', makePublic = false, episodeData } = req.body;

    if (!fileName || !content) {
      return res.status(400).json({ error: 'fileName and content required' });
    }

    const accessKeyId = process.env.ALIYUN_ACCESS_KEY_ID;
    const accessKeySecret = process.env.ALIYUN_ACCESS_KEY_SECRET;
    const bucket = process.env.ALIYUN_BUCKET;
    const region = process.env.ALIYUN_OSS_REGION || 'oss-cn-shanghai';

    // Calculate file size (content is base64 for binary files, or plain text)
    let fileSize = 0;
    if (contentType.startsWith('audio/') || contentType.startsWith('video/') || contentType.startsWith('image/')) {
      // Base64 content - calculate actual file size
      // Base64 adds ~33% overhead, so actual size = (base64_length * 3) / 4
      const base64Length = content.length;
      // Remove padding characters from calculation
      const padding = (content.match(/=/g) || []).length;
      fileSize = Math.floor((base64Length * 3) / 4) - padding;
    } else {
      // Text content - use byte length
      fileSize = Buffer.byteLength(content, 'utf8');
    }

    // Step 1: Upload file (without ACL in initial request)
    // For binary files (audio/video/image), decode base64 to binary Buffer
    let uploadBody = content;
    let contentForMD5 = content;

    if (contentType.startsWith('audio/') || contentType.startsWith('video/') || contentType.startsWith('image/')) {
      // Decode base64 to binary Buffer for upload
      uploadBody = Buffer.from(content, 'base64');
      contentForMD5 = uploadBody;
      console.log(`🔧 Decoded base64 to binary: ${content.length} chars → ${uploadBody.length} bytes`);
    }

    const contentMD5 = crypto.createHash('md5').update(contentForMD5).digest('base64');
    const date = new Date().toUTCString();

    const stringToSign = `PUT\n${contentMD5}\n${contentType}\n${date}\n/${bucket}/${fileName}`;
    const signature = crypto.createHmac('sha1', accessKeySecret).update(stringToSign).digest('base64');
    const authorization = `OSS ${accessKeyId}:${signature}`;
    const url = `https://${bucket}.${region}.aliyuncs.com/${fileName}`;

    // Upload to OSS
    const uploadResponse = await fetch(url, {
      method: 'PUT',
      headers: {
        'Authorization': authorization,
        'Date': date,
        'Content-Type': contentType,
        'Content-MD5': contentMD5
      },
      body: uploadBody  // ← Upload binary Buffer, not base64 string
    });

    if (!uploadResponse.ok) {
      const errorText = await uploadResponse.text();
      return res.status(uploadResponse.status).json({
        success: false,
        error: 'Upload failed',
        status: uploadResponse.status,
        message: errorText
      });
    }

    // Step 2: Set ACL to public-read if requested
    if (makePublic) {
      const aclDate = new Date().toUTCString();
      const aclResource = `/${bucket}/${fileName}?acl`;
      const aclStringToSign = `PUT\n\n\n${aclDate}\nx-oss-object-acl:public-read\n${aclResource}`;
      const aclSignature = crypto.createHmac('sha1', accessKeySecret).update(aclStringToSign).digest('base64');
      const aclAuthorization = `OSS ${accessKeyId}:${aclSignature}`;

      const aclResponse = await fetch(`${url}?acl`, {
        method: 'PUT',
        headers: {
          'Authorization': aclAuthorization,
          'Date': aclDate,
          'x-oss-object-acl': 'public-read'
        }
      });

      if (!aclResponse.ok) {
        const aclErrorText = await aclResponse.text();
        return res.json({
          success: true,
          url,
          fileName,
          size: fileSize,
          status: uploadResponse.status,
          message: 'File uploaded but failed to set public access',
          isPublic: false,
          aclError: aclErrorText,
          episodeData: episodeData || null  // Echo back episodeData
        });
      }
    }

    res.json({
      success: true,
      url,
      fileName,
      size: fileSize,
      status: uploadResponse.status,
      message: makePublic ? 'File uploaded successfully and is publicly accessible' : 'File uploaded successfully',
      isPublic: makePublic,
      episodeData: episodeData || null  // Echo back episodeData if provided
    });

  } catch (error) {
    console.error('Upload error:', error);
    res.status(500).json({
      error: 'Upload failed',
      message: error.message
    });
  }
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`🚀 OSS Signature API running on port ${PORT}`);
  console.log(`📝 Endpoints:`);
  console.log(`   GET  /             - Health check`);
  console.log(`   POST /oss/sign     - Generate OSS signature`);
  console.log(`   POST /oss/upload   - Upload file to OSS`);
});
