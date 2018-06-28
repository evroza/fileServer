var Sequelize = require("sequelize");
var bcrypt = require("bcrypt");
var moment = require('moment');

var saltRounds = 10;
var cleanUpInterval = 1000 * 60 * 60 * 24 //24hour


//Create db connection object
const connection = new Sequelize('users', null, null, {
	logging: false,
	operatorsAliases: Sequelize.Op,
    dialect: 'sqlite',
    storage: './db.sqlite'
});

//Create USERS table
const User = connection.define('users', {
    username: {
        type: Sequelize.STRING,
        primaryKey: true
    },
    password: Sequelize.STRING
}, {
    timestamps: false
});

//Add encryption of the password
User.beforeCreate((user, options) => {
  return cryptPassword(user.password)
  	.then(hash => {
		user.password = hash;
	})
});

//Check if hash is correct
function checkPassword (password) {
	hash = this.password;
	return bcrypt.compare(password, hash).then(function(res) {
		return res;
	});
}

User.checkPassword = checkPassword;

User.prototype.checkPassword = checkPassword;

//Create SESSIONS table
const Session = connection.define('sessions', {
	username: {
        type: Sequelize.STRING,
        references: {
            model: User,
            key: "username"
        }
    },
	token: {
    	type: Sequelize.UUID,
    	defaultValue: Sequelize.UUIDV4,
    	primaryKey: true
  	},

	expiration: Sequelize.INTEGER

}, {
    timestamps: false
});

class DuplicateKeyError extends Error{}

function cryptPassword(password) {
    return new Promise(function(resolve, reject) {
        bcrypt.hash(password, saltRounds, function(err, hash) {
			if (err) reject(err);
            else resolve(hash);
        });
    })
};

module.exports = {

	
	createDatabase: function(){
		return connection.sync({
			force: false //Overwrites the tables
		}).then(() => {
			setInterval(function(){
				Session.findAll({where: {expiration: {[Sequelize.Op.lt]: Date.now()}}})
			}, cleanUpInterval);
		}).catch(err =>{
			console.log(err);
		})
	},

	registerUser: function (user, pass, tokenAge){
		return connection.transaction(t => {
			return this.createUser(user, pass, {transaction: t})
			.then(userRow => {
				return this.createSession(user, tokenAge, {transaction: t});
			}).catch(Sequelize.UniqueConstraintError, err =>{
				throw new this.DuplicateKeyError();
			});
		})
	},

	createUser: function (user, pass, options){
		return User.create({username: user, password: pass}, options);
	},

	createSession: function (user, tokenAge, options){
		// Need to return the created session id at end of this call
        let exp = moment(new Date()).add(tokenAge,'hours').valueOf(); // token invalid after 'tokenAge' hours
		return Session.create({username: user, expiration: exp}, options);
	},

    updateSession: function (user, tokenAge, options){
		//TODO: error check incase user doesn't exist
        // Need to return the created session id at end of this call
        let exp = moment(new Date()).add(tokenAge,'hours').valueOf(); // token invalid after 'tokenAge' hours
        return Session.update({username: user, expiration: exp}, options);
    },

	retrieveUser: function (user, password){
		return User.findOne({where: {username: user}})
		.then(user => {			
			if (!user){
				console.log("ERROR: No user password of that combination found - invalid login!");
				return null;
			}				
				
			return user.checkPassword(password).then(result => {
				if (result) return user;
				else return null;
			})
		});
	},

	retrieveSessionByUser: function (user){
		return Session.findOne({where: {username: user}});
	},

	retrieveSessionByToken: function (token){
        /**
		 * Retrieves user record in session table with matching token
		 * The checks whether the token is expired, if expired return error and remove invalidate that session
		 * If token not expired then return record
         */
		return Session.findOne({where: {token: token}}).then(userSess => {
            if (!userSess)
                return null;

            // record was found, validate token time expiration
			let expiration = userSess.dataValues.expiration;
			if((Number(expiration) - moment(new Date()).valueOf()) > 0){
				// Token still valid
                return userSess;

			} else {
				// Token time expired, delete session and return error/null
				//Then return null

                deleteSessionByToken(token);
                return null;
			}


        });
	},

	deleteSessionByUser: function(user){
		return Session.destroy({where: {username: user}})
		.then((affected) =>{
			return affected;
		})
	},

	deleteSessionByToken: function(token){
		return Session.destroy({where: {token: token}})
	},

	login: function (user, pass, tokenAge){
		return this.retrieveUser(user, pass)
		.then(user => {			
			// First verify if user has active session. If so verify token expiration, if unexpired return existing token.
			// If token expired, update session with new token and tokenAge
			// If user session doesn't exist create it.
			
			//First - if user is null, it means the user pass combination is invalid, return error
			if(!user) {
				// throwing error will invoke promise rejection code
				throw new Error("The username password cobination might be incorrect, 'user' object is null!!");
			}			
			console.log("%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%");

            return this.retrieveSessionByUser(user.username).then((session) => {
                if (!session){
                    //session doesn't exist - add new
                    console.log("-1");
                    return (user ? this.createSession(user.username, tokenAge) : null)
                }

                // if here, then a session exists - verify token expiration
				let expiration = session.expiration;
                if((Number(expiration) - moment(new Date()).valueOf()) > 0){
                    console.log("0");
                    // Token still valid - return it
					return session;
				} else {
                	console.log("1");
                	// Token expired - generate new token and update expiration
					/*return this.updateSession(user.username, tokenAge, {returning: true, where: {token: session.token}}).then(updatedRow => {
						console.log("99999999999999999999999999999999", updatedRow);
						// Update success
                        return updatedRow;
                    });*/

                    return this.deleteSessionByUser(user.username).then((affectedRows) => {
                    	//Recreate the session - could have done update call instead but there were bugs with that so went this way
                        return this.createSession(user.username, tokenAge);

					})
				}

			});


		});
	},

	logout: function(token){
		return this.deleteSessionByToken(token)
		.then(affected => {
			if (affected == 1){
				console.log("User has logged out.");
				return true;
			} else {
				console.log("Session not found");
				return false;
			}
		})
	},

	DuplicateKeyError: DuplicateKeyError
}





