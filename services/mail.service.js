const nodeMailer = require('nodemailer');

const mailService = {
  connection: null,
  sendEmail(params = {}, callbackError, callbackSuccess) {
    let transporter = nodeMailer.createTransport({
        host: process.env.MAIL_SMTP_HOST,
        port: process.env.MAIL_SMTP_PORT,
        secure: true,
        auth: {
            user: process.env.MAIL_SMTP_USER,
            pass: process.env.MAIL_SMTP_PASSWORD
        }
    });
    let mailOptions = {
        from: params.from, //'"Krunal Lathiya" <xx@gmail.com>', // sender address
        to: params.to, // list of receivers
        subject: params.subject, //req.body.subject, // Subject line
        text: params.text ,//req.body.body, // plain text body
        html: params.html //'<b>NodeJS Email Tutorial</b>' // html body
    };
    transporter.sendMail(mailOptions, (error, info) => {
      if (error) {
        if (callbackError) callbackError(error);
        return console.log(error);
      }
      console.log('Message %s sent: %s', info.messageId, info.response);
      if (callbackSuccess) callbackSuccess(info);
    });
  },
  noFct() {
  },
}

module.exports = mailService;
