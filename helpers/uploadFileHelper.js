const BUCKET_NAME = process.env.AWS_BUCKET_NAME;
const fs = require('fs');
const AWS = require('aws-sdk');
const s3 = new AWS.S3({
    accessKeyId: process.env.AWS_ACCESS_KEY_ID,
    secretAccessKey: process.env.AWS_SECRET_ACCESSKEY
});
const { v4: uuidv4 } = require('uuid');

const uploadFileToLocal = {
  uploadToLocal({req, res}, destination, fileName, callbackError, callbackSuccess) {
    const multer = require('multer');
    const storage = multer.diskStorage({
        destination: destination,
        filename: function (req, file, cb) {
            console.log('MULTER filename begin', file);
            const fileName = `${uuidv4()}`;
            let format = '';
            if ( file.mimetype === 'image/jpeg' ) format = '.jpg';
            else if ( file.mimetype === 'image/png' ) format = '.png';
            else if ( file.mimetype === 'application/pdf' ) format = '.pdf';
            console.log('MULTER FINAL FILENAME', fileName+format);
            cb(null, fileName);
        }
    });

    const upload = multer({dest: __dirname + '/public/uploads/images', storage: storage}).any();
    upload(req, res, function(err) {
        if(err) {
            console.log(err);
            // return res.end("Error uploading file.");
            if (callbackError) callbackError();
        } else {
           console.log(req.body);
           req.files.forEach( function(f) {
             console.log('F', f);
             // and move file to final destination...

           });
           // res.end("File has been uploaded");
           if (callbackSuccess) callbackSuccess(req);
        }
    });
  },
  uploadFileToS3(localPathFileToCopy, destPath, callbackError, callbackSuccess) {
    // Read content from the file
    const fileContent = fs.readFileSync(localPathFileToCopy);

    // Setting up S3 upload parameters
    const params = {
        Bucket: BUCKET_NAME,
        Key: destPath, // File name you want to save as in S3
        Body: fileContent
    };

    // Uploading files to the bucket
    s3.upload(params, function(err, data) {
        if (err) {
            if (callbackError) callbackError(err);
            throw err;
        }
        if (callbackSuccess) callbackSuccess(data);
    });
  },
  async deleteFileOnS3(destPath, callbackError, callbackSuccess) {
    const deleteParams = {
      Bucket: BUCKET_NAME,
      Delete: {
        Objects: [{
          Key: destPath
        }]
      }
    };
    await s3.deleteObjects(deleteParams).promise();
    await callbackSuccess();
  },
  async emptyS3Directory(userId, callbackError, callbackSuccess) {
    const listParams = {
      Bucket: BUCKET_NAME,
      Prefix: userId
    };
    const listedObjects = await s3.listObjectsV2(listParams).promise();
    if (listedObjects.Contents.length === 0) {
      await callbackSuccess();
      return;
    }
    const deleteParams = {
      Bucket: BUCKET_NAME,
      Delete: {
        Objects: []
      }
    };
    deleteParams.Delete.Objects = listedObjects.Contents.map(({
      Key
    }) => ({Key: Key}));
    await s3.deleteObjects(deleteParams).promise();
    if (listedObjects.IsTruncated) {
      await emptyS3Directory(userId);
    }
  }
}

module.exports = uploadFileToLocal;
