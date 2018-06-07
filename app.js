var express = require("express");
var cookieParser = require("cookie-parser");
var bodyParser = require("body-parser");

var DbApi = require("./libs/DbApi");

var app = express();
app.set("view engine", "ejs");
app.use(bodyParser.urlencoded({
    extended: true
}))

app.use(cookieParser("He just kept talking in one long incredibly unbroken sentence, moving from topic to topic..."));

DbApi.createDatabase(); //Create if not exists

app.get("/", (req, res) => {
    console.log(req.signedCookies);
    res.render("home");
})

app.get("/login", (req, res) => {
 	res.render("login");
});

app.post("/login", (req, res) => {

	DbApi.login(req.body.username, req.body.password, tokenAge)
	.then(session => {
		if (session != null){
			addUserSession(session.token, res);
			res.redirect("/secret");
		} else {
			res.status(403);
			res.render("login", {error: "Wrong username or password."});
		}
	}).catch(err => {
		console.log(err);
				
		res.status(401);
		res.render("login", {error: "There was an error. Please try again in a few moments."});
	});

});

app.get("/signup", (req, res) => {
    res.render("signup");
});

app.post("/signup", (req, res) => {
	DbApi.registerUser(req.body.username, req.body.password, tokenAge)
	.then(session => {
			addUserSession(session.token, res);
			res.redirect("/secret");
	}).catch(DbApi.DuplicateKeyError, err => {
		res.status(409);
		res.render("signup", {error: "Username already taken"});	
	}).catch(err => {
		console.log(err);
	});
});

app.get("/secret", isAuthenticated, (req, res) => {
	res.render("user", {username: req.username})
});

app.get('/logout', (req, res) => {
    var token = req.signedCookies.session;

	DbApi.logout(token)
	.then(result => {
		if (result){
			removeUserSession(res);
		} else {
			console.log('Session not found. Redirect to /login');
		}
		res.redirect('/login');
	});

});

app.listen(3000, () => {
    console.log("Server has started on http://127.0.0.1:3000");
})

function isAuthenticated(req, res, next){
    if(req.signedCookies.session){
		DbApi.retrieveSessionByToken(req.signedCookies.session)
		.then(session => {
			if (!session){
				res.redirect("/login");
			}
			req.username = session.username;
			return next();
		}).catch(err => {
			console.log(err);
		});
    } else {
		res.status(401)
		res.render("login");
	}
}

var tokenAge = 604800000; //1week

function addUserSession (token, res){
	res.cookie("session", token, {
		httpOnly: true,
		maxAge: tokenAge,
		signed: true,
		// secure: true	//put it to true if behind https
	})
}

function removeUserSession (res){
	res.clearCookie("session");
}


