const dotenv = require('dotenv');
dotenv.config();
const express = require('express');
const cors = require('cors')
const app = express();
const fs = require('fs')
const url = require('url');
const bodyParser = require('body-parser')
const jsonParser = bodyParser.json()
const bcrypt = require("bcryptjs");
const auth = require("./helpers/auth");
const port = process.env.NODE_ENV === 'production' ? 8080 : process.env.PORT;
const mysqlService = require('./services/mysql.service');
const mailService = require('./services/mail.service');
const loggerService = require('./services/logger.service');
mysqlService.init();
const dateHelper = require('./helpers/date.helper');
const tokenHelper = require('./helpers/token.helper');
const uploadFileHelper = require('./helpers/uploadFileHelper');
const { v4: uuidv4 } = require('uuid');
// CORS
app.use(cors({
  origin: ['http://localhost:3000', 'https://localhost:8080', 'http://localhost:4000',
    "https://front-build-public.s3.eu-west-3.amazonaws.com"
  ],
}));
// app.options('*', cors());

app.use(express.json({limit: '50mb'}));
app.use(express.urlencoded({limit: '50mb'}));
app.use(bodyParser.urlencoded({
    extended: true
}));



// app.use(bodyParser.json()) // old version
const APP_NUMBER_MATCH_PER_X = process.env.APP_NUMBER_MATCH_PER_X;
const APP_NUMBER_MATCH_X_TIME_HOURS = process.env.APP_NUMBER_MATCH_X_TIME_HOURS;

// serve images, CSS files, and JavaScript files in a directory named public
app.use('/public', express.static('public'))


app.get('/', (req, res) => {
	console.log ('req: ', req);
	return res.send('Hello World!');
});

app.post('/register', jsonParser, (req, res) => {
  loggerService.logger.info(`register req.body: ${JSON.stringify(req.body)}`);

	console.log ('req.url', req.url);
	console.log ('req.body', req.body);
	const isFacebookLogin = !!req.body.fb_authResponse;
	let email, password, birtday, name = null, fb_id, fb_object = null, gender;
	if (isFacebookLogin) {
    if (!req.body.fb_me.email) {
      return res.send({error: {code: 401, text: 'Email is needed, please fill an email in your FB account or allow your email in the app authorization'}});
    }
		email = req.body.fb_me.email.toLowerCase();
		password = '';
		birtday = dateHelper.formatDateForMysql(req.body.fb_me.birthday);
		fb_id = req.body.fb_me.id;
		name = req.body.fb_me.name;
		fb_object = JSON.stringify(req.body.fb_authResponse);
		gender = req.body.fb_me.gender
	} else {
		email = req.body.email.toLowerCase();
		password = req.body.password;
		bcrypt.hash(password, 10, function(err, hash) {
			password = hash; // encrypt password
		});
		birtday = dateHelper.formatDateForMysql(`${req.body.yearOfBirth.name}-${req.body.monthOfBirth.name}-${req.body.dayOfBirth.name}`);
		gender = req.body.gender.value;
	}
  const isLegalAge = dateHelper.isLegalAge(birtday);
  if (!isLegalAge) { return res.send({error: {code: 401, text: 'Legal Age not Permit'}}); }
  // Create token
  let token = tokenHelper.generateToken();
  let refresh_token = tokenHelper.generateToken();
  const looking_for = gender === 'male' ? 'female' : 'male';
  // HERE
  const created_at = dateHelper.formatDateForMysql();

	// check user already exist
	mysqlService.query('SELECT * FROM user WHERE email = ? LIMIT 1',
		[email], (error) => {
			console.log('register error', error);
		}, (userExist) => {
			console.log('register userExist', userExist);
			if (userExist.length === 0) {
				console.log('register createUser BEGIN');
				mysqlService.query('INSERT INTO user (token, refresh_token, email, password, birtday, name, fb_id, fb_object, gender, looking_for, created_at ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)',
				[token, refresh_token, email, password, birtday, name, fb_id, fb_object, gender, looking_for, created_at], (error) => {
					console.log('register user creation error', error);
					return res.send({error: {code: 500, text: 'Creation user Error'}});
				}, (userCreated) => {
					console.log('register userCreated', userCreated);
					// return user created
					mysqlService.query('SELECT * FROM user WHERE email = ? LIMIT 1',
					[email], (error) => {
						console.log('register error', error);
					}, (userGoodCreated) => {
						console.log('register userGoodCreated', userGoodCreated);
						return res.send({success: {code:200, text: 'User is Created', token: token, refresh_token:refresh_token, user: userGoodCreated}});
					});
        });
    } else {
        const continueFct = (user) => {
          user = user.map(el => (Object.assign(el, {pictures: JSON.parse(el.pictures)}))); // transform pictures
          // check if facebook register
          if(isFacebookLogin) {
            return res.send({success: {code: 200, text: 'Facebook User Already Exist', token: user[0].token, refresh_token: user[0].refresh_token, user: user}});
          } else {
            return res.send({error: {code: null, text: 'Email already exist'}});
          }
        }
        if (!userExist[0].token) {
          // generate new token
          mysqlService.query('UPDATE user SET token = ?, refresh_token = ? WHERE id = ? LIMIT 1',
          [token, refresh_token, userExist[0].id], (error) => {
            console.log('register user update token error', error);
            return res.send({error: {code: 500, text: 'register user update token Error'}});
          }, (userTokenCreated) => {
            userExist[0].token = token;
            userExist[0].refresh_token = refresh_token;
            continueFct(userExist);
          });
        } else {
          continueFct(userExist);
        }
      }
    });
});

app.post('/login', (req, res) => {
	console.log ('login req.url', req.url);
	console.log ('login req.body', req.body);
	let email = req.body.email, password = req.body.password;
  if (!email) return res.send({success: {code: 401, text: 'Login Error, provide an email'}});
  if (!password) return res.send({success: {code: 401, text: 'Login Error, provide a password'}});
	mysqlService.query('SELECT * FROM user WHERE email = ? LIMIT 1',
	[email], (error) => {
			console.log('login error', error);
			return res.send({error: {code: 404, text: 'Email user not Exist'}});
	}, (userEmail) => {
			console.log('login userEmail', userEmail);
      if (!userEmail[0]) return res.send({error: {code: 401, text: 'Login Error, user email not exist'}});
			console.log('login userEmail.password', userEmail[0].password);
			console.log('login password', password);
			bcrypt.compare(password, userEmail[0].password).then((isSamePassword) => {
				console.log('login isSamePassword', isSamePassword);
				if (isSamePassword === true) { // password hash is same
				  let token = tokenHelper.generateToken();
				  let refresh_token = tokenHelper.generateToken();
				  // update token in user profile and send result?
				  mysqlService.query('UPDATE user SET token = ?, refresh_token = ? WHERE email = ? LIMIT 1',
					[token, refresh_token, email], (error) => {
						console.log('login error', error);
						return res.send({error: {code: 500, text: 'Token not stored in the user profile'}});
					}, (tokenInserted) => {
						console.log('login tokenInserted', tokenInserted);
            userEmail = userEmail.map(el => (Object.assign(el, {pictures: JSON.parse(el.pictures)}))); // transform pictures
						userEmail.token = token;
						userEmail.refresh_token = refresh_token;
						return res.send({success: {code: 200, text: 'Login success and token updated', token: token, user: userEmail}});
					});
				} else {
					// password is not same, return error to customer
					return res.send({error: {code: 401, text: 'Password do not match'}});
				}
			});
	});
});

app.post('/logout', (req, res) => {
  console.log ('logout req.url', req.url);
  console.log ('logout req.body', req.body);
  let token = tokenHelper.getToken(req);
  mysqlService.query('SELECT * FROM user WHERE token = ? LIMIT 1',
  [token], (error) => {
      console.log('logout error', error);
      return res.send({error: {code: 404, text: 'Email user not Exist'}});
  }, (user) => {
      console.log('logout user', user);
      if (!user.length) {
        return res.send({success: {code: 404, text: 'Logout Success - no user found'}});
      }
      // remove token in this account
      mysqlService.query('UPDATE user SET token = ?, refresh_token = ? WHERE id = ? LIMIT 1',
      ['', '', user[0].id], (error) => {
          console.log('logout update user error', error);
          return res.send({error: {code: 500, text: 'update user pictures in database error'}});
      }, (success) => {
        console.log('logout update user success', success);
        return res.send({success: {code: 200, text: 'Logout Success'}});
      });
  });
});

app.post('/reset-password-send-email', (req, res) => {
  console.log ('reset-password req.url', req.url);
  console.log ('reset-password req.body', req.body);
  const email = req.body.email
  // let token = tokenHelper.getToken(req);
  mysqlService.query('SELECT * FROM user WHERE email = ? LIMIT 1',
  [email], (error) => {
      console.log('reset-password error', error);
      return res.send({error: {code: 404, text: 'Email user not Exist'}});
  }, (user) => {
      console.log('reset-password from email user.length', user.length);
      if (!user.length) {
        return res.send({success: {code: 404, text: 'ERROR: no user found from the email'}});
      }
      // update the reset token
      const reset_password_token = tokenHelper.generateToken('15m'); // short token to securise the password generation
      mysqlService.query('UPDATE user SET reset_password_token = ? WHERE id = ? LIMIT 1',
      [reset_password_token, user[0].id], (error) => {
        console.log('reset-password update user error', error);
        return res.send({error: {code: 500, text: 'Reset Link token error'}});
      }, (success) => {
        console.log('reset-password update user reset link success', success);
        const mailParams = {
          from: '"Meet And Places" <xx@gmail.com>',
          to: user[0].email,
          subject: 'Reset Password Email',
          html: `<h3>Please click the link below to reset your password</h3>
            <p>${process.env.FRONT_APP_URL}/#/reset-password/${reset_password_token}</p>`
        };
        mailService.sendEmail(mailParams, (error) => {
          return res.send({success: {code: 500, text: 'Email not send, ERROR, please contact support'}});
        }, (success) => {
          return res.send({success: {code: 200, text: 'An Email was sent to your addresse, please check your mailbox and Spam folder'}});
        });
      });
  });
});

app.post('/reset-password', (req, res) => {
  console.log ('reset-password req.url', req.url);
  console.log ('reset-password req.body', req.body);
  const reset_password_token = req.body.reset_password_token;
  //first check the token is still valid
  const tokenIsValid = tokenHelper.verifyToken(reset_password_token);
  console.log ('reset-password tokenIsValid', tokenIsValid);
  if (!tokenIsValid) return res.send({success: {code: 401, text: 'ERROR: token is not valid anymore, please use a fresh link'}});
  let password = req.body.password1;
  // return res.send({success: {code: 200, text: 'Password is updated, please connect to the app'}});
  bcrypt.hash(password, 10, (err, hash) => {
    password = hash; // encrypt password
    mysqlService.query('UPDATE user SET password = ? WHERE reset_password_token = ? LIMIT 1',
    [password, reset_password_token], (error) => {
        console.log('reset-password error', error);
        return res.send({error: {code: 404, text: 'Update password error'}});
    }, (passwordUpdated) => {
        console.log('reset-password from reset_password_token', passwordUpdated);
        return res.send({success: {code: 200, text: 'Password updated, please connect to the app'}});
    });
  });
});

app.post('/delete-my-profil', (req, res) => {
  console.log ('delete-my-profil req.url', req.url);
  console.log ('delete-my-profil req.body', req.body);
  let token = tokenHelper.getToken(req);
  mysqlService.query('SELECT * FROM user WHERE token = ? LIMIT 1',
  [token], (error) => {
      console.log('delete-my-profil error', error);
      return res.send({error: {code: 404, text: 'Email user not Exist'}});
  }, (user) => {
      console.log('delete-my-profil user', user);
      if (!user.length) {
        return res.send({success: {code: 404, text: 'Deletion aborted - no user found'}});
      }
      // delete pictures
      const pathToS3 = `${user[0].id}/`;
      console.log('pathToS3', pathToS3);
      uploadFileHelper.emptyS3Directory(pathToS3, (error) => {
        console.log('delete-my-profil delete file error', error);
        return res.send({error: {code: 500, text: 'delete pictures error'}});
      }, (fileDeleted) => {
        console.log('delete-my-profil delete file error', fileDeleted);
        // remove in database the messages
        mysqlService.query('DELETE FROM messages WHERE id_user_sender = ? or id_user_receiver = ?',
        [user[0].id, user[0].id], (error) => {
            console.log('delete-my-profil error', error);
            return res.send({error: {code: 500, text: 'delete-my-profil messages error'}});
        }, (messageDeleted) => {
            console.log('delete-my-profil message deleted');
            // delete matchs
            mysqlService.query('DELETE FROM match_table WHERE id_user_sender = ? or id_user_receiver = ?',
            [user[0].id, user[0].id], (error) => {
                console.log('delete-my-profil error', error);
                return res.send({error: {code: 404, text: 'delete-my-profil matchs error'}});
            }, (matchsDeleted) => {
                console.log('delete-my-profil match deleted');
                // delete user
                mysqlService.query('DELETE FROM user WHERE id = ?',
                [user[0].id], (error) => {
                    console.log('delete-my-profil user error', error);
                    return res.send({error: {code: 404, text: 'delete-my-profil user error'}});
                }, (matchsDeleted) => {
                    console.log('delete-my-profil match deleted');
                    // delete user
                    return res.send({success: {code: 200, text: 'Full Deletion OK- Profil no longer exist in the system'}});
                });
            });
        });
      });
  });
});

app.post('/refresh', (req, res) => {
	console.log ('login req.url', req.url);
	console.log ('login req.body', req.body);
	let refresh_token = req.body.refresh_token;
	if(!refresh_token) return res.send({error: {code: 404, text: 'Please send a refresh_token'}});
	mysqlService.query('SELECT * FROM user WHERE refresh_token = ? LIMIT 1',
	[refresh_token], (error) => {
		console.log('refresh error', error);
		return res.send({error: {code: 404, text: 'refresh error'}});
	}, (user) => {
		console.log('refresh user token exist user length', user.length);
    if(!user.length) {
      return res.status(500).send({error: {code: 500, text: 'no user found with this refresh_token, please full login', needLogin: true}});
    }
		// generate new token and send it
		let new_refresh_token = tokenHelper.generateToken();
		let token = tokenHelper.generateToken();
    console.log('new_refresh_token', new_refresh_token);
    console.log('token', token);
		// update token in user profile and send result?
		mysqlService.query('UPDATE user SET token = ?, refresh_token = ? WHERE refresh_token = ? LIMIT 1',
		[token, new_refresh_token, refresh_token], (error) => {
			console.log('refresh insert token error', error);
			return res.send({error: {code: 500, text: 'Token not stored in the user profile'}});
		}, (tokenInserted) => {
			console.log('refresh tokenInserted');
			user.token = token;
			user.refresh_token = new_refresh_token;
      user = user.map(el => (Object.assign(el, {pictures: JSON.parse(el.pictures)}))); // transform pictures
			return res.send({success: {code: 200, text: 'Refresh token success', token: token, refresh_token: new_refresh_token, user: user}});
		});
	});
});

app.get('/me', auth, (req, res) => {
	console.log ('me req.url', req.url);
	console.log ('me req.body', req.body);
	let token = tokenHelper.getToken(req);

	mysqlService.query('SELECT * FROM user WHERE token = ? LIMIT 1',
	[token], (error) => {
		console.log('me error', error);
		return res.send({error: {code: 404, text: 'Me user no found'}});
	}, (user) => {
		console.log('me user');
    if (!user.length) return res.status(401).send({error: {code: 401, text: 'Me user not found from token'}});
    if (user.length) {
		  user[0].pictures = JSON.parse(user[0].pictures) || [];
    }
    // update the last_activity date
    const last_activity = dateHelper.formatDateForMysql();
    mysqlService.query('UPDATE user SET last_activity = ? WHERE id = ? LIMIT 1',
    [last_activity, user[0].id], (error) => {
      console.log('me insert last activity error', error);
      return res.send({error: {code: 500, text: 'me insert last activity error'}});
    }, (lastActivityInserted) => {
      console.log('me insert last activity ');
      return res.send({success: {code: 200, text: 'Me user', user: user}});
    });
	});
});

app.post('/upload-picture', auth, (req, res) => {
  // console.log ('upload-picture req', req);
  console.log ('upload-picture req.fields', req.fields);
  console.log ('upload-picture req.url', req.url);
	console.log ('upload-picture req.body', req.body);

	let token = tokenHelper.getToken(req);
	mysqlService.query('SELECT * FROM user WHERE token = ? LIMIT 1',
	[token], (error) => {
		console.log('upload-picture error', error);
		return res.send({error: {code: 404, text: 'Me user no found'}});
	}, (user) => {
    if (!user.length) return res.status(401).send({error: {code: 401, text: 'Me user not found from token, need to refresh the token'}});
		console.log('upload-picture user', user[0]);
    const destination = `./public/uploads/images/${user[0].id}`;
    const filenameWithoutExtension = `${user[0].id}_${uuidv4()}`;
		uploadFileHelper.uploadToLocal({req, res}, destination, filenameWithoutExtension, (error) => {
			console.log('upload-picture uploadFileToLocal error', error);
			return res.send({error: {code: 500, text: 'Upload file to local Error'}});
		}, (localUpload) => {
			console.log('upload-picture uploadFileToLocal success', localUpload.files);
      let imgCpt = 0;
      let s3imgArray = [];
			for (var i = localUpload.files.length - 1; i >= 0; i--) {
				const pathToS3 = `profiles/${user[0].id}/${localUpload.files[i].filename}`;
				console.log('upload-picture pathToS3', pathToS3);
				uploadFileHelper.uploadFileToS3(localUpload.files[i].path, pathToS3, (error) => {
				  console.log('upload-picture uploadFileToS3 error', error);
				  return res.send({error: {code: 500, text: 'Upload file to S3 Error'}});
				}, (s3upload) => {
          s3imgArray.push(s3upload.Location);
          imgCpt++;
          console.log('imgCpt', imgCpt);
          console.log('localUpload.files.length - 1', localUpload.files.length - 1);
          console.log('localUpload.files.length', localUpload.files.length);
          if (imgCpt === localUpload.files.length) {
            //all img are processed
            console.log('upload-picture uploadFileToS3 success', s3imgArray);
  					let pictures = JSON.parse(user[0].pictures) || [];
  					console.log('upload-picture uploadFileToS3 sucess pictures', pictures);
  					for (var i = s3imgArray.length - 1; i >= 0; i--) {
              pictures.push(s3imgArray[i]);
            }
  					picturesToSave = JSON.stringify(pictures);
  					// save in database the image object
  					mysqlService.query('UPDATE user SET pictures = ? WHERE id = ? LIMIT 1',
  					[picturesToSave, user[0].id], (error) => {
  				  	  console.log('upload-picture update user pictures error', error);
  				  	  return res.send({error: {code: 500, text: 'update user pictures in database error'}});
  					}, (success) => {
  					  console.log('upload-picture update user pictures success', success);
  				  	  user[0].pictures = pictures;
  					  return res.send({success: {code: 200, text: 'Picture Added', user: user}});
  					});
          }
				});
			}
		});
	});
});

app.post('/update-picture-order', auth, (req, res) => {
  console.log ('update-picture-order req.url', req.url);
  console.log ('update-picture-order req.body', req.body);
  const pictures = req.body.pictures;
  let token = tokenHelper.getToken(req);
  mysqlService.query('SELECT * FROM user WHERE token = ? LIMIT 1',
  [token], (error) => {
    console.log('update-picture-order error', error);
    return res.send({error: {code: 404, text: 'Me user no found'}});
  }, (user) => {
    console.log('update-picture-order user', user[0]);
    //update the picture order
    const newPictures = JSON.stringify(pictures);
    mysqlService.query('UPDATE user SET pictures = ? WHERE id = ? LIMIT 1',
    [newPictures, user[0].id], (error) => {
      console.log('update-picture-order error', error);
      return res.send({error: {code: 404, text: 'Picture Deleted Error'}});
    }, (success) => {
      console.log('update-picture-order success', success);
      user.pictures = pictures;
      return res.send({success: {code: 200, text: 'Picture successfull Ordered', user: user}});
    });
  });
});

app.post('/remove-picture', auth, (req, res) => {
	console.log ('remove-picture req.url', req.url);
	console.log ('remove-picture req.body', req.body);
	let token = tokenHelper.getToken(req);
	mysqlService.query('SELECT * FROM user WHERE token = ? LIMIT 1',
	[token], (error) => {
		console.log('remove-picture error', error);
		return res.send({error: {code: 404, text: 'Me user no found'}});
	}, (user) => {
		console.log('remove-picture user', user[0]);
		const pathWithoutDomain = url.parse(req.body.image).pathname
		console.log('remove-picture pathWithoutDomain', pathWithoutDomain);
		// TODO: recreate the folder level with the user_id (included in the url currently)
		let pathToS3 = `${pathWithoutDomain}`;
    pathToS3 = pathToS3.substring(1);
		console.log('remove-picture pathToS3', pathToS3);
		uploadFileHelper.deleteFileOnS3(pathToS3, (error) => {
		  console.log('remove-picture error', error);
		  return res.send({error: {code: 404, text: 'Delete file on S3 Error'}});
		}, (deletedFileS3) => {
      console.log('remove-picture success delete s3', deletedFileS3);
      // update the mysql object
      user[0].pictures = JSON.parse(user[0].pictures);
      console.log('remove-picture before update picture object', user[0].pictures);
      // filter picture to delete
      user[0].pictures = user[0].pictures.filter(function(value, index, arr){
        return value !== req.body.image;
      });
      console.log('remove-picture before AFTER picture object', user[0].pictures);
      const newPictures = JSON.stringify(user[0].pictures);
      mysqlService.query('UPDATE user SET pictures = ? WHERE id = ? LIMIT 1',
      [newPictures, user[0].id], (error) => {
        console.log('remove-picture update after delete error', error);
        return res.send({error: {code: 404, text: 'Picture Deleted Error'}});
      }, (success) => {
        console.log('remove-picture update after delete success', success);
        return res.send({success: {code: 200, text: 'Picture successfull Deleted', user: user}});
      });
		});
	});
});

app.post('/update-profile', auth, (req, res) => {
  console.log ('update-profile req.url', req.url);
  console.log ('update-profile req.body', req.body);
  const token = tokenHelper.getToken(req);
  const listParams = Object.keys(req.body);
  let sqlArray = [];
  let sqlString = 'UPDATE user SET ';
  // generate sql query function of params
  for (var i = listParams.length - 1; i >= 0; i--) {
    console.log('update-profile req.body[listParams[i]]', req.body[listParams[i]]);
    if (!req.body[listParams[i]]) continue;

    if (listParams[i] === 'age_search') { // age exeption min and max
      sqlArray.push(req.body[listParams[i]].min)
      sqlString += `age_search_min = ?, `;
      sqlArray.push(req.body[listParams[i]].max)
      sqlString += `age_search_max = ?`;
    } else if (listParams[i] === 'height_wanted') { // height_wanted exeption min and max
      sqlArray.push(req.body[listParams[i]].min)
      sqlString += `height_wanted_min = ?, `;
      sqlArray.push(req.body[listParams[i]].max)
      sqlString += `height_wanted_max = ?`;
    } else if (req.body[listParams[i]].name !== undefined) { // dropdown case
      sqlArray.push(req.body[listParams[i]].name);
      sqlString += `${listParams[i]} = ?`;
    } else {
      sqlArray.push(req.body[listParams[i]]);
      sqlString += `${listParams[i]} = ?`;
    }
    if (i > 0) {
      sqlString += ', '
    }
  }
  sqlArray.push(token);
  sqlString += ` WHERE token = ? LIMIT 1`;
  console.log('sqlString', sqlString);
  console.log('sqlArray', sqlArray);
  mysqlService.query(sqlString,
  sqlArray, (error) => {
    console.log('update-profile update', error);
    return res.send({error: {code: 404, text: 'update-profile update Error'}});
  }, (success) => {
    console.log('update-profile update success', success);
    return res.send({success: {code: 200, text: 'update-profile'}});
  });
});

app.post('/report-delete-match', auth, (req, res) => {
  console.log ('report-delete-match req.url', req.url);
  console.log ('report-delete-match req.body', req.body);
  const id_user_receiver = req.body.id_user_receiver;
  const token = tokenHelper.getToken(req);
  const report = req.body.report;
  const created_at = dateHelper.formatDateForMysql();
  const deleted_at = dateHelper.formatDateForMysql();

  if (!id_user_receiver) return res.send({success: {code: 200, text: 'Please send id_user_receiver param'}});

  mysqlService.query('SELECT * FROM user WHERE token = ? LIMIT 1',
  [token], (error) => {
    console.log('report-delete-match error', error);
    return res.send({error: {code: 404, text: 'Match search user Error'}});
  }, (my_user) => {
    console.log('report-delete-match success', my_user);
    // first report user
    if (report) {
      // insert report occurence
      mysqlService.query(`INSERT INTO user_reported (id_user_sender, id_user_receiver, created_at, report) VALUES (?, ?, ?, ?)`,
      [my_user[0].id, id_user_receiver, created_at, report], (error) => {
        console.log('report-delete-match insert report error', error);
        return res.send({error: {code: 404, text: 'Match search user Error'}});
      }, (reportInserted) => {
        console.log('report-delete-match insert report success', reportInserted);
        return res.send({success: {code: 200, text: 'report-delete-match success'}});
      });
    }
    // delete match - flag the match to not have it again
    mysqlService.query(`UPDATE match_table SET deleted_at = ? WHERE (id_user_sender = ? AND id_user_receiver = ?) OR (id_user_sender = ? AND id_user_receiver = ?) LIMIT 2`,
    [deleted_at, my_user[0].id, id_user_receiver, id_user_receiver, my_user[0].id], (error) => {
      console.log('report-delete-match set deleted error', error);
      return res.send({error: {code: 404, text: 'Match search user Error'}});
    }, (matchsDeleted) => {
      console.log('report-delete-match set deleted success', matchsDeleted);

      // remove in database the messages
      mysqlService.query('DELETE FROM messages WHERE (id_user_sender = ? AND id_user_receiver = ?) OR (id_user_sender = ? AND id_user_receiver = ?)',
      [my_user[0].id, id_user_receiver, id_user_receiver, my_user[0].id], (error) => {
          console.log('report-delete-match error', error);
          return res.send({error: {code: 500, text: 'delete-my-profil messages error'}});
      }, (messageDeleted) => {
          console.log('report-delete-match message deleted', messageDeleted);
          return res.send({success: {code: 200, text: 'report-delete-match matchsDeleted messageDeleted success'}});
      });
    });
  });
});

app.post('/match', auth, (req, res) => {
	console.log ('match req.url', req.url);
	console.log ('match req.body', req.body);
  // insert eh geolocation into the user record
  const token = tokenHelper.getToken(req);
  const my_position = JSON.stringify(req.body.my_position);
  const my_position_latitude = req.body.my_position.coords.latitude;
  const my_position_longitude = req.body.my_position.coords.longitude;
  const my_user_id = req.body.my_user.id;
  const distance_search = req.body.my_user.distance_search;
  const age_search_min = req.body.my_user.age_search_min;
  const age_search_max = req.body.my_user.age_search_max;
  const date_age_search_min = dateHelper.getBirthDateOfDateAge(age_search_min);
  const date_age_search_max = dateHelper.getBirthDateOfDateAge(age_search_max);
  const looking_for = req.body.my_user.looking_for;
  const gender_wanted = looking_for === 'both' ? "'male','female'" : `'${looking_for}'`;

  const startlat = my_position_latitude;
  const startlng = my_position_longitude;
  const sqlMatchsLimit = 50; // 50 profil in match return request

  mysqlService.query('UPDATE user SET my_position = ?, my_position_latitude = ?, my_position_longitude = ? WHERE token = ? LIMIT 1',
  [my_position, my_position_latitude, my_position_longitude, token], (error) => {
    console.log('match update my_position error', error);
    return res.send({error: {code: 500, text: 'Match update my position Error'}});
  }, (positionUpdated) => {
    console.log('match update my_position', positionUpdated);
    // get list of id already matched to not have it in the match results
    mysqlService.query('SELECT id_user_receiver FROM match_table WHERE id_user_sender = ?',
    [my_user_id], (error) => {
      console.log('match get already exist error', error);
      return res.send({error: {code: 404, text: 'Match search user Error'}});
    }, (users) => {
      console.log('match get already exist my_user_id', my_user_id);
      // console.log('match get already exist users', users);
      let list_id_ignore = users.map(a => a.id_user_receiver);
      list_id_ignore.push(my_user_id);
      list_id_ignore = list_id_ignore.join(',');
      console.log('match list_id_ignore', list_id_ignore);
      mysqlService.query(`
        SELECT *, my_position_latitude, my_position_longitude, 
        SQRT(POW(69.1 * (my_position_latitude - ?), 2) + POW(69.1 * (? - my_position_longitude) * COS(my_position_latitude / 57.3), 2)) AS distance
        FROM user
        WHERE user.id NOT IN (${list_id_ignore}) 
        AND birtday >= '${date_age_search_max}' AND birtday <= '${date_age_search_min}' 
        AND gender IN (${gender_wanted}) 
        AND pictures is NOT NULL 
        HAVING distance <= ? 
        ORDER BY distance 
        LIMIT ?
      `,
      [startlat, startlng, distance_search, sqlMatchsLimit], (error) => {
        console.log('match error', error);
        return res.send({error: {code: 404, text: 'Match search user Error'}});
      }, (users) => {
        console.log('match users', users);
        console.log('match users success');
        users = users.map(el => (Object.assign(el, {pictures: JSON.parse(el.pictures)}))); // transform pictures
        return res.send({success: {code: 200, text: 'Match user results', user: users}});
      });
    });
  });
});

app.post('/set-match', auth, (req, res) => {
  console.log ('set-match req.url', req.url);
  console.log ('set-match req.body', req.body);
  const token = tokenHelper.getToken(req);
  // const id_user_sender = req.body.my_user.id; // not used, use token
  const id_user_receiver = req.body.user_matched_id;
  const match_value = req.body.match_value;
  const created_at = dateHelper.formatDateForMysql();

  // count number match done by the user since period
  // APP_NUMBER_MATCH_PER_X
  // APP_NUMBER_MATCH_X_TIME_HOURS

  mysqlService.query('SELECT * FROM user WHERE token = ? LIMIT 1',
  [token], (error) => {
    console.log('set-match get MY user error', error);
    return res.send({error: {code: 404, text: 'set-match no token found'}});
  }, (my_user) => {
    console.log('set-match get MY user from token success');
    const id_user_sender = my_user[0].id;
    const last_date_to_check = dateHelper.getDateMinusXHours(APP_NUMBER_MATCH_X_TIME_HOURS);
    mysqlService.query(`SELECT MAX(created_at) AS last_activity, COUNT(*) AS count FROM match_table WHERE id_user_sender = ? AND created_at >= '${last_date_to_check}'`,
    [id_user_sender], (error) => {
      console.log('set-match check matchs error', error);
    }, (countAlreadyMatched) => {
      console.log('set-match check matchs success', countAlreadyMatched);
      if (countAlreadyMatched[0].count > APP_NUMBER_MATCH_PER_X) {
        // calcul time
        const nextDate = dateHelper.getDateMinusXHours(-APP_NUMBER_MATCH_X_TIME_HOURS);
        return res.send({success: {code: 401, text: 'Number match for period already done, please wait', nextDate: nextDate}});
      } else {
        mysqlService.query('INSERT INTO match_table (id_user_sender, id_user_receiver, match_value, created_at) VALUES (?, ?, ?, ?)',
        [id_user_sender, id_user_receiver, match_value, created_at], (error) => {
          console.log('set-match error', error);
          return res.send({error: {code: 404, text: 'set-match search user Error', isMatch: false}});
        }, (setMatchSuccess) => {
          console.log('set-match success', setMatchSuccess);
          if (match_value === false) {
            return res.send({success: {code: 200, text: 'Match false value Inserted, you say no', isMatch: false}});  
          }
          // check a match already exist for this one and create a message and send a notification
          mysqlService.query(`SELECT * FROM match_table WHERE id_user_sender = ? AND id_user_receiver = ? AND match_value = 1 LIMIT 1`,
          [id_user_receiver, id_user_sender], (error) => {
            console.log('match check already error', error);
            return res.send({error: {code: 404, text: 'Match check already Error', isMatch: false}});
          }, (checkAlreadyMatched) => {
            console.log('match check already', checkAlreadyMatched);
            console.log('match check already .length', checkAlreadyMatched.length);
            if (checkAlreadyMatched.length === 0) {
              return res.send({success: {code: 200, text: 'Match Inserted - check already results - no match already registered', isMatch: false}});  
            } else {
              // get the user matched and send it to the front end
              mysqlService.query(`SELECT * FROM user WHERE id = ? LIMIT 1`,
              [id_user_receiver], (error) => {
                console.log('match get matched user', error);
                return res.send({error: {code: 404, text: 'Match get matched user Error', isMatch: false}});
              }, (matchedUser) => {
                console.log('match get matched user', matchedUser);
                matchedUser = matchedUser.map(el => (Object.assign(el, {pictures: JSON.parse(el.pictures)}))); // transform pictures
                const message_content = `You have matched with: ${matchedUser[0].name}`;
                // create a message for theses user to comunicate
                mysqlService.query(`INSERT INTO messages (id_user_sender, id_user_receiver, created_at, message_content) VALUES (?, ?, ?, ?)`,
                [id_user_receiver, id_user_sender, created_at, message_content], (error) => {
                  console.log('match insert message error', error);
                  return res.send({error: {code: 404, text: 'Match search user Error', isMatch: false}});
                }, (insertedMessage) => {
                  console.log('match insert message ', insertedMessage);
                  // users = users.map(el => (Object.assign(el, {pictures: JSON.parse(el.pictures)}))); // transform pictures
                  // return res.send({success: {code: 200, text: 'Match user results', user: users}});
                  return res.send({success: {code: 200, text: 'Matched user results, messag inserted', userMatched: matchedUser, isMatch: true}});
                });
              });
            }
          });
        });
      }
    });
  });
});

app.post('/threads-messages', auth, (req, res) => {
  console.log ('threads-messages req.url', req.url);
  console.log ('threads-messages req.body', req.body);
  const token = tokenHelper.getToken(req);
  const sqlLimit = 13; // get last 50 threads
  const page = req.body.page || 0;
  const sqlOffset = page * sqlLimit;

  mysqlService.query('SELECT * FROM user WHERE token = ? LIMIT 1',
  [token], (error) => {
    console.log('threads-messages get MY user error', error);
    return res.send({error: {code: 404, text: 'threads-messages no refresh token found'}});
  }, (my_user) => {
    console.log('threads-messages get MY user from token success');
    mysqlService.query(`
      SELECT *,
      temp_table.created_at as messages_created_at 
      FROM ((
       SELECT *, id_user_sender as theuser_id FROM messages
       WHERE messages.id_user_receiver = ${my_user[0].id}
      ) UNION (
       SELECT *, id_user_receiver as theuser_id FROM messages
       WHERE messages.id_user_sender = ${my_user[0].id}
      )) AS temp_table
      INNER JOIN user ON user.id = theuser_id
      GROUP BY theuser_id
      order by temp_table.created_at desc
      LIMIT ${sqlLimit}
      OFFSET ${sqlOffset}
      `,
    [], (error) => {
      console.log('threads-messages error', error);
      return res.send({error: {code: 404, text: 'threads-messages Error'}});
    }, (users) => {
      console.log('threads-messages get threads users.length', users.length);
      // delete the thread linked to my user
      users = users.filter(el => el.id !== my_user[0].id);
      // reaasign pictures object
      users = users.map(el => (Object.assign(el, {pictures: JSON.parse(el.pictures)}))); // transform pictures
      return res.send({success: {code: 200, text: 'threads-messages results', user: users, page: page}});
    });
  })
});

app.post('/thread-messages', auth, (req, res) => {
  console.log ('thread-messages req.url', req.url);
  console.log ('thread-messages req.body', req.body);
  const token = tokenHelper.getToken(req);
  const id_receiver = req.body.id_receiver;
  const sqlLimit = 15; // get last 150 messages
  const page = req.body.page || 0;
  const sqlOffset = page * sqlLimit;
  mysqlService.query('SELECT * FROM user WHERE token = ? LIMIT 1',
  [token], (error) => {
    console.log('threads-messages get MY user error', error);
    return res.send({error: {code: 404, text: 'no refresh token found'}});
  }, (my_user) => {
    console.log('threads-messages get MY user from token success', my_user);
    mysqlService.query(`SELECT * FROM messages
      WHERE (messages.id_user_sender = ? AND messages.id_user_receiver = ?)
      OR  (messages.id_user_receiver = ? AND messages.id_user_sender = ?)
      ORDER BY messages.created_at DESC
      LIMIT ? OFFSET ?`,
    [my_user[0].id, id_receiver, my_user[0].id, id_receiver, sqlLimit, sqlOffset], (error) => {
      console.log('thread-messages error', error);
      return res.send({error: {code: 404, text: 'threads-messages Error'}});
    }, (messages) => {
      // console.log('thread-messages get threads users', messages);
      messages = messages.reverse(); // reverse message to have it in good order

      // users = users.map(el => (Object.assign(el, {pictures: JSON.parse(el.pictures)}))); // transform pictures
      return res.send({success: {code: 200, text: 'Match user results', messages: messages, page: page}});
    });
  })
});

app.post('/send-messages', auth, (req, res) => {
  console.log ('send-messages req.url', req.url);
  console.log ('send-messages req.body', req.body);
  const token = tokenHelper.getToken(req);
  const id_user_receiver = req.body.id_user_receiver;
  const id_user_sender = req.body.id_user_sender;
  const message_content = req.body.message_content;
  const created_at = dateHelper.formatDateForMysql();
  // const sqlLimit = 150; // get last 150 messages
  mysqlService.query('SELECT * FROM user WHERE token = ? LIMIT 1',
  [token], (error) => {
    console.log('send-messages get MY user error', error);
    return res.send({error: {code: 404, text: 'no refresh token found'}});
  }, (my_user) => {
    console.log('send-messages get MY user from token success', my_user);
    mysqlService.query(`INSERT INTO messages (id_user_sender, id_user_receiver, created_at, message_content) VALUES (?, ?, ?, ?)`,
    [id_user_sender, id_user_receiver, created_at, message_content], (error) => {
      console.log('send-messages insert message error', error);
      return res.send({error: {code: 404, text: 'Match search user Error'}});
    }, (insertedMessage) => {
      console.log('send-messages insert message ', insertedMessage);
      // users = users.map(el => (Object.assign(el, {pictures: JSON.parse(el.pictures)}))); // transform pictures
      // return res.send({success: {code: 200, text: 'Match user results', user: users}});
      return res.send({success: {code: 200, text: 'send-messages message inserted'}});
    });
  })
});

app.post('/contact-us', auth, (req, res) => {
  console.log ('contact-us req.url', req.url);
  console.log ('contact-us req.body', req.body);
  const token = tokenHelper.getToken(req);
  const title_message = req.body.title;
  const message = req.body.message;
  const created_at = dateHelper.formatDateForMysql();
  // const sqlLimit = 150; // get last 150 messages
  mysqlService.query('SELECT * FROM user WHERE token = ? LIMIT 1',
  [token], (error) => {
    console.log('contact-us get MY user error', error);
    return res.send({error: {code: 404, text: 'no refresh token found'}});
  }, (my_user) => {
    console.log('contact-us get MY user from token success');
    mysqlService.query(`INSERT INTO contact_us (user_id, title, created_at, message) VALUES (?, ?, ?, ?)`,
    [my_user[0].id, title_message, created_at, message], (error) => {
      console.log('contact-us message error', error);
      return res.send({error: {code: 404, text: 'contact-us insert message Error'}});
    }, (insertedMessage) => {
      console.log('contact-us insert message ');
      // users = users.map(el => (Object.assign(el, {pictures: JSON.parse(el.pictures)}))); // transform pictures
      // return res.send({success: {code: 200, text: 'Match user results', user: users}});
      return res.send({success: {code: 200, text: 'contact-us success'}});
    });
  })
});

app.get('/event-categories', auth, (req, res) => {
  console.log ('events-categories req.url', req.url);
  console.log ('events-categories req.body', req.body);
  // const sqlLimit = 150; // get last 150 messages
  mysqlService.query('SELECT * FROM category_event WHERE 1',
  [], (error) => {
    console.log('events-categories get categories', error);
    return res.send({error: {code: 404, text: 'events-categories get categories error'}});
  }, (categories) => {
    console.log('events-categories get categories success', categories);
    return res.send({success: {code: 200, text: 'events-categories success', categories: categories}});
  })
});

app.post('/event-create', auth, (req, res) => {
  console.log ('event-create req.url', req.url);
  console.log ('event-create req.body', req.body);
  const token = tokenHelper.getToken(req);
  const created_at = dateHelper.formatDateForMysql();
  const updated_at = dateHelper.formatDateForMysql();
  const id_category_event = req.body.category.id;
  const title = req.body.title;
  const date = req.body.date;
  const number_people_wanted = req.body.numberPeoplesWanted;
  const event_description = req.body.description;
  const formatted_address = req.body.formatted_address;
  const event_geolocation_latitude = req.body.position.latitude;
  const event_geolocation_longitude = req.body.position.longitude;
  if (!event_geolocation_latitude || !event_geolocation_longitude) return res.send({error: {code: 404, text: 'event-create Please put a location'}});
  // const sqlLimit = 150; // get last 150 messages
  mysqlService.query('SELECT * FROM user WHERE token = ? LIMIT 1',
  [token], (error) => {
    console.log('event-create get MY user error', error);
    return res.send({error: {code: 404, text: 'no refresh token found'}});
  }, (my_user) => {
    console.log('event-create get MY user from token success');
    mysqlService.query(`INSERT INTO event (id_user, id_category_event, title, date, number_people_wanted, event_description, formatted_address, event_geolocation_latitude, event_geolocation_longitude, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
    [my_user[0].id, id_category_event, title, date, number_people_wanted, event_description, formatted_address, event_geolocation_latitude, event_geolocation_longitude, created_at, updated_at], (error) => {
      console.log('event-create message error', error);
      return res.send({error: {code: 404, text: 'event-create insert message Error'}});
    }, (insertedEvent) => {
      console.log('event-create insert event ', insertedEvent);
      const id_event = insertedEvent.insertId;
      console.log('event-create insert event id inserted', insertedEvent.insertId);
      // users = users.map(el => (Object.assign(el, {pictures: JSON.parse(el.pictures)}))); // transform pictures
      // return res.send({success: {code: 200, text: 'Match user results', user: users}});
      return res.send({success: {code: 200, text: 'event-create success', event_id: insertedEvent.insertId}});
    });
  })
});
 
app.post('/event-update', auth, (req, res) => {
  console.log ('event-update req.url', req.url);
  console.log ('event-update req.body', req.body);
  const token = tokenHelper.getToken(req);
  const event_id = req.body.event_id;
  const updated_at = dateHelper.formatDateForMysql();
  const id_category_event = req.body.category.id;
  const title = req.body.title;
  const date = req.body.date;
  const number_people_wanted = req.body.numberPeoplesWanted;
  const event_description = req.body.description;
  const formatted_address = req.body.formatted_address;
  const event_geolocation_latitude = req.body.position && req.body.position.latitude; // facultatif on update
  const event_geolocation_longitude = req.body.position && req.body.position.longitude; // facultatif on update
  // const sqlLimit = 150; // get last 150 messages
  mysqlService.query('SELECT * FROM user WHERE token = ? LIMIT 1',
  [token], (error) => {
    console.log('event-update get MY user error', error);
    return res.send({error: {code: 404, text: 'no refresh token found'}});
  }, (my_user) => {
    console.log('event-update get MY user from token success');
    let queryString = `UPDATE event SET id_category_event = ?, title = ?, date = ?, number_people_wanted = ?, event_description = ?, updated_at = ?`
    let arrayValues = [id_category_event, title, date, number_people_wanted, event_description, updated_at];
    if (event_geolocation_latitude && event_geolocation_latitude) {
      queryString += `, formatted_address=? `; arrayValues.push(formatted_address);
      queryString += `, event_geolocation_latitude=? `; arrayValues.push(event_geolocation_latitude);
      queryString += `, event_geolocation_longitude=? `; arrayValues.push(event_geolocation_longitude);
    }
    queryString += ` WHERE event.id = ?`; arrayValues.push(event_id);
    mysqlService.query(`${queryString}`,
    arrayValues, (error) => {
      console.log('event-update message error', error);
      return res.send({error: {code: 404, text: 'event-update insert message Error'}});
    }, (updatedEvent) => {
      console.log('event-update update event ', updatedEvent);

      mysqlService.query(`SELECT *, 
        SQRT(POW(69.1 * (event_geolocation_latitude - ${my_user[0].my_position_latitude}), 2) + POW(69.1 * (${my_user[0].my_position_longitude} - event_geolocation_longitude) * COS(event_geolocation_latitude / 57.3), 2)) AS distance,
        event.id as event_id, user.id as user_id
        FROM event
        INNER JOIN category_event ON event.id_category_event = category_event.id
        INNER JOIN user ON event.id_user = user.id
        WHERE event.id = ?`,
      [event_id], (error) => {
        console.log('event-update get event after update error', error);
        return res.send({error: {code: 404, text: 'event-update insert message Error'}});
      }, (event) => {
        console.log('event-update get event after update ', event);
        
        event = event.map(el => (Object.assign(el, {
          event_pictures: JSON.parse(el.event_pictures),
          pictures: JSON.parse(el.pictures) 
        }))); // transform pictures
        // return res.send({success: {code: 200, text: 'Match user results', user: users}});
        return res.send({success: {code: 200, text: 'event-update success', event: event }});
      });

    });
  })
});

const multer = require("multer");
const destinationImgFolder = __dirname + '/public/uploads/images';
const storage = multer.diskStorage({
    destination: destinationImgFolder,
    filename: function (req, file, cb) {
        const fileName = `${uuidv4()}`;
        console.log('MULTER filename begin', file);
        let format = '';
        if ( file.mimetype === 'image/jpeg' ) format = '.jpg';
        else if ( file.mimetype === 'image/png' ) format = '.png';
        else if ( file.mimetype === 'application/pdf' ) format = '.pdf';
        console.log('MULTER FINAL FILENAME', fileName+format);
        cb(null, fileName+format);
    }
});

const upload = multer({ dest: destinationImgFolder, storage: storage });

app.post('/event-upload-picture', auth, upload.array("image[]"), (req, res) => {
  // console.log ('upload-picture req', req);
  console.log ('upload-picture req.files', req.files);
  console.log ('upload-picture req.url', req.url);
  console.log ('upload-picture req.body', req.body);
  const event_id = req.body.event_id;
  console.log('event_id', event_id);

  mysqlService.query(`
    SELECT *, 
    event.id as event_id, user.id as user_id
    FROM event
    INNER JOIN category_event ON event.id_category_event = category_event.id
    INNER JOIN user ON event.id_user = user.id
    WHERE event.id = ? 
    LIMIT 1`,
  [event_id], (error) => {
    console.log('event-upload-picture get event error', error);
    return res.send({error: {code: 404, text: 'Me user no found'}});
  }, (event) => {
    event = event.map(el => (Object.assign(el, {
      pictures: JSON.parse(el.pictures) || [],
      event_pictures: JSON.parse(el.event_pictures) || [],
    }))); // transform pictures
    console.log('event-upload-picture get event success PICS', event[0].event_pictures);
    let imgCpt = 0;
    let s3imgArray = [];
    const files = req.files;
    console.log('event-upload-picture files', files);
    // no files to upload
    if (!files.length) return res.send({success: {code: 200, text: 'No picture to add', event: event}});
    // files to upload
    for (var i = files.length - 1; i >= 0; i--) {
      const pathToS3 = `events/${event_id}/${files[i].filename}`;
      console.log('upload-picture pathToS3', pathToS3);
      uploadFileHelper.uploadFileToS3(files[i].path, pathToS3, (error) => {
        console.log('upload-picture uploadFileToS3 error', error);
        return res.send({error: {code: 500, text: 'Upload file to S3 Error'}});
      }, (s3upload) => {
        s3imgArray.push(s3upload.Location);
        imgCpt++;
        console.log('imgCpt', imgCpt);
        console.log('files.length - 1', files.length - 1);
        console.log('files.length', files.length);
        if (imgCpt === files.length) {
          //all img are processed
          console.log('upload-picture uploadFileToS3 success', s3imgArray);
          let pictures = event[0].event_pictures;
          console.log('upload-picture uploadFileToS3 sucess pictures', pictures);
          for (var i = s3imgArray.length - 1; i >= 0; i--) {
            pictures.push(s3imgArray[i]);
          }
          picturesToSave = JSON.stringify(pictures);
          // save in database the image object
          mysqlService.query('UPDATE event SET event_pictures = ? WHERE event.id = ? LIMIT 1',
          [picturesToSave, event_id], (error) => {
              console.log('upload-picture event pictures error', error);
              return res.send({error: {code: 500, text: 'update event pictures in database error'}});
          }, (success) => {
            console.log('upload-picture event pictures success', success);
              event[0].event_pictures = pictures;
            return res.send({success: {code: 200, text: 'Picture Added', event: event}});
          });
        }
      });
    }
  });
});

app.post('/update-event-picture-order', auth, (req, res) => {
  console.log ('update-event-picture-order req.url', req.url);
  console.log ('update-event-picture-order req.body', req.body);
  const pictures = req.body.pictures;
  const event_id = req.body.event_id;

  let token = tokenHelper.getToken(req);
  mysqlService.query(`
    SELECT *, 
    event.id as event_id, user.id as user_id
    FROM event
    INNER JOIN category_event ON event.id_category_event = category_event.id
    INNER JOIN user ON event.id_user = user.id
    WHERE event.id = ? 
    LIMIT 1
  `,
  [event_id], (error) => {
    console.log('update-event-picture-order error', error);
    return res.send({error: {code: 404, text: 'event no found'}});
  }, (event) => {
    console.log('update-event-picture-order event');
    //update the picture order
    const newPictures = JSON.stringify(pictures);
    mysqlService.query('UPDATE event SET event_pictures = ? WHERE id = ? LIMIT 1',
    [newPictures, event[0].id], (error) => {
      console.log('update-event-picture-order error');
      return res.send({error: {code: 404, text: 'Picture RE-Order Error'}});
    }, (success) => {
      console.log('update-event-picture-order success');
      event[0].event_pictures = pictures;
      return res.send({success: {code: 200, text: 'Picture event successfull Ordered', event: event}});
    });
  });
});

app.post('/remove-event-picture', auth, (req, res) => {
  console.log ('remove-event-picture req.url', req.url);
  console.log ('remove-event-picture req.body', req.body);
  const event_id = req.body.event_id;
  const picture = req.body.picture;

  let token = tokenHelper.getToken(req);
  mysqlService.query('SELECT * FROM event WHERE id = ? LIMIT 1',
  [event_id], (error) => {
    console.log('remove-event-picture error', error);
    return res.send({error: {code: 404, text: 'Me user no found'}});
  }, (event) => {
    console.log('remove-event-picture event', event[0]);
    const pathWithoutDomain = url.parse(picture).pathname
    console.log('remove-event-picture pathWithoutDomain', pathWithoutDomain);
    // TODO: recreate the folder level with the user_id (included in the url currently)
    let pathToS3 = `${pathWithoutDomain}`;
    pathToS3 = pathToS3.substring(1);
    console.log('remove-event-picture pathToS3', pathToS3);
    uploadFileHelper.deleteFileOnS3(pathToS3, (error) => {
      console.log('remove-event-picture error', error);
      return res.send({error: {code: 404, text: 'Delete file on S3 Error'}});
    }, (deletedFileS3) => {
      console.log('remove-event-picture success delete s3', deletedFileS3);
      // update the mysql object
      event[0].event_pictures = JSON.parse(event[0].event_pictures);
      console.log('remove-event-picture before update picture object', event[0].event_pictures);
      // filter picture to delete
      event[0].event_pictures = event[0].event_pictures.filter(function(value, index, arr){
        return value !== picture;
      });
      console.log('remove-event-picture before AFTER picture object', event[0].event_pictures);
      const newPictures = JSON.stringify(event[0].event_pictures);
      mysqlService.query('UPDATE event SET event_pictures = ? WHERE id = ? LIMIT 1',
      [newPictures, event[0].id], (error) => {
        console.log('remove-event-picture update after delete error', error);
        return res.send({error: {code: 404, text: 'Picture Deleted Error'}});
      }, (success) => {
        console.log('remove-event-picture update after delete success', success);
        return res.send({success: {code: 200, text: 'Picture successfull Deleted', event: event}});
      });
    });
  });
});

app.post('/events', auth, (req, res) => {
  console.log ('events req.url', req.url);
  console.log ('events req.body', req.body);
  const token = tokenHelper.getToken(req);
  const sqlLimit = 13; // get last 50 threads
  const dateEvents = req.body.date;
  const page = req.body.page || 0;
  const sqlOffset = page * sqlLimit;
  const user_offset = req.body.offset;
  console.log('user_offset', user_offset);
  let dateBegin = new Date(new Date(dateEvents).setUTCHours(0, 0, 0, 0)); // UTC begin of day
  let dateEnd = new Date(new Date(dateEvents).setUTCHours(23, 59, 59, 999)); // UTC end of day
  dateBegin = dateHelper.getUserDateFromOffset(dateBegin, user_offset); // convert into user timezone
  dateEnd = dateHelper.getUserDateFromOffset(dateEnd, user_offset); // convert into user timezone
  console.log('/events dateEvents', dateEvents);
  console.log('/events dateBegin', dateBegin);
  console.log('/events dateEnd', dateEnd);
  mysqlService.query('SELECT * FROM user WHERE token = ? LIMIT 1',
  [token], (error) => {
    console.log('events get MY user error', error);
    return res.send({error: {code: 404, text: 'events no refresh token found'}});
  }, (my_user) => {
    console.log('events get MY user from token success my_user.length', my_user.length);
    mysqlService.query(`
      SELECT *, 
      SQRT(POW(69.1 * (event_geolocation_latitude - ${my_user[0].my_position_latitude}), 2) + POW(69.1 * (${my_user[0].my_position_longitude} - event_geolocation_longitude) * COS(event_geolocation_latitude / 57.3), 2)) AS distance,
      event.id as event_id, user.id as user_id
      FROM event
      INNER JOIN category_event ON event.id_category_event = category_event.id
      INNER JOIN user ON event.id_user = user.id
      WHERE date <= "${dateEnd}" AND date >= "${dateBegin}"
      HAVING distance <= ${my_user[0].distance_search}
      order by date asc
      `,
      // LIMIT ${sqlLimit}
      // OFFSET ${sqlOffset}
    [], (error) => {
      console.log('events error', error);
      return res.send({error: {code: 404, text: 'events Error'}});
    }, (events) => {
      console.log('events get events.length', events.length);
      events = events.map(el => (Object.assign(el, {
        event_pictures: JSON.parse(el.event_pictures),
        pictures: JSON.parse(el.pictures) 
      }))); // transform pictures
      return res.send({success: {code: 200, text: 'events results', events: events, page: page}});
    });
  })
});

app.post('/event-participate', auth, (req, res) => {
  console.log ('event-participate req.url', req.url);
  console.log ('event-participate req.body', req.body);
  const token = tokenHelper.getToken(req);
  const sqlLimit = 13; // get last 50 threads
  const event_id = req.body.event_id;
  const created_at = dateHelper.formatDateForMysql();

  mysqlService.query('SELECT * FROM user WHERE token = ? LIMIT 1',
  [token], (error) => {
    console.log('event-participate get MY user error', error);
    return res.send({error: {code: 404, text: 'events no refresh token found'}});
  }, (my_user) => {
    console.log('event-participate get MY user from token success');
    mysqlService.query(`
      INSERT INTO user_participate_event ( id_user, id_event, status, created_at ) 
      VALUES (?, ?, ?, ?)
      ON DUPLICATE KEY UPDATE created_at = ?
      `,
    [my_user[0].id, event_id, 'pending', created_at, created_at], (error) => {
      console.log('event-participate error', error);
      return res.send({error: {code: 404, text: 'events Error'}});
    }, (insertedEventRelation) => {
      console.log('event-participate insertedEventRelation');
      return res.send({success: {code: 200, text: 'events participation success' }});
    });
  })
});

app.post('/event-approve-participant', auth, (req, res) => {
  console.log ('event-approve-participant req.url', req.url);
  console.log ('event-approve-participant req.body', req.body);
  const token = tokenHelper.getToken(req);
  // const sqlLimit = 13; // get last 50 threads
  const id_event = req.body.id_event;
  const id_user = req.body.id_user;
  const status_changed_at = dateHelper.formatDateForMysql();
  const status_wanted = req.body.status_wanted;
  mysqlService.query('SELECT * FROM user WHERE token = ? LIMIT 1',
  [token], (error) => {
    console.log('event-approve-participant get MY user error', error);
    return res.send({error: {code: 404, text: 'events no refresh token found'}});
  }, (my_user) => {
    console.log('event-approve-participant get MY user from token success');
    mysqlService.query(`
      UPDATE user_participate_event SET 
      status = ?, status_changed_at = ? 
      WHERE id_event = ? AND id_user = ?
      LIMIT 1
      `,
    [status_wanted, status_changed_at, id_event, id_user], (error) => {
      console.log('event-approve-participant error', error);
      return res.send({error: {code: 404, text: 'events Error'}});
    }, (insertedEventRelation) => {
      console.log('event-approve-participant insertedEventRelation');
      return res.send({success: {code: 200, text: 'events participation success', status_wanted: status_wanted }});
    });
  })
});

app.post('/event-remove-participate', auth, (req, res) => {
  console.log ('event-remove-participate req.url', req.url);
  console.log ('event-remove-participate req.body', req.body);
  const token = tokenHelper.getToken(req);
  const sqlLimit = 13; // get last 50 threads
  const event_id = req.body.event_id;
  const created_at = dateHelper.formatDateForMysql();

  mysqlService.query('SELECT * FROM user WHERE token = ? LIMIT 1',
  [token], (error) => {
    console.log('event-remove-participate get MY user error', error);
    return res.send({error: {code: 404, text: 'events no refresh token found'}});
  }, (my_user) => {
    if (!my_user.length) return res.status(401).send({error: {code: 401, text: 'Me user not found from token, need to refresh the token'}});
    console.log('event-remove-participate get MY user from token success', my_user);
    mysqlService.query(`
      DELETE FROM user_participate_event WHERE id_user = ? AND id_event = ?
      `,
    [my_user[0].id, event_id], (error) => {
      console.log('event-remove-participate error', error);
      return res.send({error: {code: 404, text: 'events Error'}});
    }, (insertedEventRelation) => {
      console.log('event-remove-participate insertedEventRelation', insertedEventRelation);
      return res.send({success: {code: 200, text: 'events participation success' }});
    });
  })
});

app.post('/get-event-participate', auth, (req, res) => {
  console.log ('get-event-participate req.url', req.url);
  console.log ('get-event-participate req.body', req.body);
  const token = tokenHelper.getToken(req);
  const sqlLimit = 13; // get last 50 threads
  const event_id = req.body.event_id;
  const created_at = dateHelper.formatDateForMysql();

  mysqlService.query('SELECT * FROM user WHERE token = ? LIMIT 1',
  [token], (error) => {
    console.log('get-event-participate get MY user error', error);
    return res.send({error: {code: 404, text: 'events no refresh token found'}});
  }, (my_user) => {
    console.log('get-event-participate get MY user from token success');
    mysqlService.query(`
      SELECT *
      FROM user_participate_event
      INNER JOIN user ON user.id = user_participate_event.id_user 
      WHERE id_event = ?
      `,
    [event_id], (error) => {
      console.log('get-event-participate error', error);
      return res.send({error: {code: 404, text: 'events Error'}});
    }, (eventParticipations) => {
      console.log('get-event-participate eventParticipations');
      eventParticipations = eventParticipations.map(el => (Object.assign(el, { pictures: JSON.parse(el.pictures) }))); // transform pictures
      return res.send({success: {code: 200, text: 'events participation success', participations: eventParticipations }});
    });
  })
});

app.post('/event-add-comment', auth, (req, res) => {
  console.log ('event-add-comment req.url', req.url);
  console.log ('event-add-comment req.body', req.body);
  const token = tokenHelper.getToken(req);
  // const sqlLimit = 13; // get last 50 threads
  const id_event = req.body.event_id;
  const created_at = dateHelper.formatDateForMysql();
  const event_comment_message = req.body.event_comment_message;
  if (!event_comment_message) return res.send({error: {code: 500, text: 'Pleae Add a message'}});
  mysqlService.query('SELECT * FROM user WHERE token = ? LIMIT 1',
  [token], (error) => {
    console.log('event-add-comment get MY user error', error);
    return res.send({error: {code: 404, text: 'events no refresh token found'}});
  }, (my_user) => {
    console.log('event-add-comment get MY user from token success');
    mysqlService.query(`
      INSERT INTO event_comments ( id_event, id_user, event_comment_message, created_at ) 
      VALUES (?, ?, ?, ?)
      `,
    [id_event, my_user[0].id, event_comment_message, created_at], (error) => {
      console.log('event-add-comment error', error);
      return res.send({error: {code: 404, text: 'events Error'}});
    }, (insertedEventComment) => {
      console.log('event-add-comment insertedEventRelation', insertedEventComment);
      const id_comment = insertedEventComment.insertId
      return res.send({success: {code: 200, text: 'events participation success', id_comment: id_comment }});
    });
  })
});

app.post('/event-delete-comment', auth, (req, res) => {
  console.log ('event-delete-comment req.url', req.url);
  console.log ('event-delete-comment req.body', req.body);
  const token = tokenHelper.getToken(req);
  // const sqlLimit = 13; // get last 50 threads
  const comment_id = req.body.comment_id;
  const id_event = req.body.id_event;
  const created_at = dateHelper.formatDateForMysql();
  const event_comment_message = req.body.event_comment_message;
  if (!event_comment_message) return res.send({error: {code: 500, text: 'Pleae Add a message'}});
  mysqlService.query('SELECT * FROM user WHERE token = ? LIMIT 1',
  [token], (error) => {
    console.log('event-delete-comment get MY user error', error);
    return res.send({error: {code: 404, text: 'events no refresh token found'}});
  }, (my_user) => {
    console.log('event-delete-comment get MY user from token success');
    mysqlService.query(`
      DELETE FROM event_comments 
      WHERE id = ? AND id_user = ? AND id_event = ?
      `,
    [comment_id, my_user[0].id, id_event], (error) => {
      console.log('event-delete-comment error', error);
      return res.send({error: {code: 404, text: 'events Error'}});
    }, (deletedComment) => {
      console.log('event-delete-comment insertedEventRelation', deletedComment);
      return res.send({success: {code: 200, text: 'Comment deletion success' }});
    });
  })
});

app.post('/get-event-comments', auth, (req, res) => {
  console.log ('get-event-comments req.url', req.url);
  console.log ('get-event-comments req.body', req.body);
  const token = tokenHelper.getToken(req);
  const sqlLimit = 13; // get last 50 threads
  const event_id = req.body.event_id;
  const created_at = dateHelper.formatDateForMysql();

  mysqlService.query('SELECT * FROM user WHERE token = ? LIMIT 1',
  [token], (error) => {
    console.log('get-event-comments get MY user error', error);
    return res.send({error: {code: 404, text: 'events no refresh token found'}});
  }, (my_user) => {
    console.log('get-event-comments get MY user from token success');
    mysqlService.query(`
      SELECT *,
      event_comments.created_at as event_comments_created_at,
      event_comments.id as comment_id,
      event_comments.id_user as event_comments_id_user
      FROM event_comments
      INNER JOIN user ON user.id = event_comments.id_user 
      WHERE id_event = ?
      ORDER BY event_comments.created_at DESC
      `,
    [event_id], (error) => {
      console.log('get-event-comments error', error);
      return res.send({error: {code: 404, text: 'events Error'}});
    }, (eventComments) => {
      console.log('get-event-comments eventComments');
      eventComments = eventComments.map(el => (Object.assign(el, { pictures: JSON.parse(el.pictures) }))); // transform pictures
      return res.send({success: {code: 200, text: 'events participation success', comments: eventComments }});
    });
  })
});

app.get('/boilerplate', auth, (req, res) => {
	console.log ('me req.url', req.url);
	console.log ('me req.body', req.body);
	return res.send({success: {code: 200, text: 'Me user', user: user}});
});

// app.listen(port, '0.0.0.0');
app.listen(port, function() {
  console.log('Server running at http://127.0.0.1:%s', port);
  loggerService.logger.info(`Server running at http://127.0.0.1:${port}'`);
});

// mysqlService.query(`SELECT * FROM user HAVING distance < ? ORDER BY distance LIMIT ?`,
// [startlat, startlng, my_user_id, distance_search, sqlLimit], (error) => {
//   console.log('match error', error);
//   return res.send({error: {code: 404, text: 'Match search user Error'}});
// }, (users) => {
//   console.log('match users', users);
//   users = users.map(el => (Object.assign(el, {pictures: JSON.parse(el.pictures)}))); // transform pictures
//   return res.send({success: {code: 200, text: 'Match user results', user: users}});
// });