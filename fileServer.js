/**
 * Created by Evans R. on 6/7/2018.
 */

var express = require("express");
var cookieParser = require("cookie-parser");
var bodyParser = require("body-parser");

var fs = require('fs');


var DbApi = require("./libs/dbApi");

var app = express();
app.set("view engine", "ejs");

app.use(bodyParser.urlencoded({ extended: true }));
app.use(bodyParser.json());

app.use(cookieParser("Some sentence I just wrote to use in cookie generation, it is random indeed !$@#65#@%&%65..."));
var tokenAge = 24; //24hours

DbApi.createDatabase(); //Create if not exists




app.get("/login", (req, res) => {
    res.render("login");
});

app.post("/login", (req, res) => {
    // must submit both username and password in post. otherwise fail and return error json
    let username = req.body.username;
    let password = req.body.password;

    if(typeof username === 'string' && typeof password === 'string'){
        // login
        DbApi.login(username, password, tokenAge)
            .then(session => {
                console.log(session, "w-----------------")
                if (session != null){
                    console.log("User successfully logged in. Token: ", session.dataValues.token);
                    // Return token to authenticated user
                    res.setHeader('Content-Type', 'application/json');
                    res.send(JSON.stringify({ token: session.dataValues.token, status: "success" }));

                } else {
                    // user unauthorized
                    res.status(403);
                    res.setHeader('Content-Type', 'application/json');
                    res.send(JSON.stringify({ message: "The username|password combination submitted is incorrect", status: "error" }));
                }
            }).catch(err => {
            console.log("ERROR: Possible promise rejection because of user|password incorrectness");

            //res.render("login", {message: "There was an error. Please try again in a few moments.", status: "error"});
			//return error response json
			res.status(403);
			res.setHeader('Content-Type', 'application/json');
			res.send(JSON.stringify({ message: "The username|password combination submitted is incorrect", status: "error" }));
        });
    } else {
        // fail and return json error message
        console.log("Either username or password is missing or incorrectly configured in post message");
        res.setHeader('Content-Type', 'application/json');
        res.send(JSON.stringify({ message: "Login unsuccessful. Username or password is missing in request. Check API documentation for correct configuration", status: "error" }));
    }



});




app.post("/save", isAuthenticated, (req, res) => {
    let clientIP = req.headers['x-forwarded-for'] || req.connection.remoteAddress;
    console.log("Token: ", req.headers.authorization);
	
	console.log("========================================================================");
	console.log(req.body);
	console.log("========================================================================");

    // If autheniticated - save file dataset in payload into unique  file containing timestamp and ip of sender
    // File name format -->  timestamp_ipAddress.txt
    // Check dataset exists and save it, if not then save an empty string
    // Log that no dataset was received
    let content = JSON.stringify(req.body.dataset) || '';

    let fileName = '';
    fileName += new Date().getTime() + '_.txt';
    //fileName += clientIP;

    fs.writeFile("datasets/" + fileName, content, function(err) {
        if(err) {
            console.log("Unspecified I/O error occured. Dataset write to disk failed!");

            res.status(501);
            res.setHeader('Content-Type', 'application/json');
            res.send(JSON.stringify({ message: "Dataset save failed. Unspecified server error!", status: "error" }));
            return console.log(err);

        }

        console.log("Data Set has been logged to file: ", fileName);
    });

    // Return success message to client
    //res.render("home");

    res.setHeader('Content-Type', 'application/json');
    res.send(JSON.stringify({ message: "Dataset successfully saved to file!", status: "success" }));
});


app.get("/signup", (req, res) => {
    res.render("signup");
});

/**
 * This endpoint can be triggered either via post or webpage. If via webpage then post data obtained from form fields.
 * If triggered via direct post to this api, the user registration data obtained from post fields
 */
app.post("/signup", (req, res) => {
    console.log("New client sign up initiated");

    DbApi.registerUser(req.body.username, req.body.password, tokenAge)
        .then(session => {
            //return payload in response
            res.setHeader('Content-Type', 'application/json');
            res.send(JSON.stringify({ token: session.token }));
        }).catch(DbApi.DuplicateKeyError, err => {
            console.error("Error-Signup: Username already taken");

            res.status(409);
            res.setHeader('Content-Type', 'application/json');
            res.send(JSON.stringify({ message: "Username already taken", status: "error" }));
    }).catch(err => {
        console.log(err);
    });
});


app.post('/logout', (req, res) => {
    let token = req.body.token;
    let username = req.body.username;

    // if token or username was sent then logout user, otherwise return error message - token|username to be expired must be in post
    if(typeof req.body.token === 'string' || typeof req.body.username === 'string'){
        // at least one was passed
        // try login out by username if fails try token if both fail then
        try {
            DbApi.deleteSessionByUser(username).then((sess) => {
                console.log(sess);
            });
        } catch (err) {
            console.log(err);
        }

    }

    DbApi.logout(token)
        .then(result => {
            if (result){
                console.log('User has been logged out. Token destroyed');

                res.setHeader('Content-Type', 'application/json');
                res.send(JSON.stringify({ message: "Logout succesful. Try logging in again to access api", status: "success" }));
            } else {
                console.log('Session not found. Redirect to /login');
            }
            res.redirect('/login');
        });

});


/**
 * Must have token generation function - purpose is to generate and replace/store to db against username
 * @param req
 * @param res
 * @param next
 */


function isAuthenticated(req, res, next){
    /**
     * Authentication process - check if Authorization token exist in header and verify against stored value in db exists in db
     * If it does success -> forward to endpoint
     * If token doesn't exist then deny access - 401
     *
     * The actual login happens in a different endpoint
     **/

    let token = req.headers.authorization;

    if(typeof req.headers.authorization === 'string'){ // a token was submitted - verify it
        DbApi.retrieveSessionByToken(token)
            .then(session => {
                if (!session){
                    res.status(401);
                    // Submit error messages
                    res.setHeader('Content-Type', 'application/json');
                    res.send(JSON.stringify({ message: "Invalid token submitted!", status:"error" }));
                    //return next();
                } else{
					req.username = session.username;
					// The token verification was successful!
					console.log("User token successfully verified! Token:", token);
					return next();
				}                
            }).catch(err => {
            console.log(err);
        });

    } else {
        res.status(401);
        // Submit error messages
        res.setHeader('Content-Type', 'application/json');
        res.send(JSON.stringify({ message: "Authorization header is missing in your request. Please check API documentation!", status:"error" }));
        //return next();
    }
}




app.listen(3000, () => {
    console.log("Server has started on http://127.0.0.1:3000");
})