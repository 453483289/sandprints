var express= require('express');
var mongoose = require('mongoose');
var app = express();
var bodyParser = require('body-parser');
var async = require('async');
var expressValidator = require('express-validator');
var passport = require('passport');
var flash    = require('connect-flash');
var session      = require('express-session');
var bcrypt   = require('bcrypt-nodejs');
var LocalStrategy   = require('passport-local').Strategy;
var cookieParser = require('cookie-parser');
var path = require('path');




app.set('view engine', 'pug');
app.set('views','./views');
app.use(express.static('public'))
app.use(bodyParser.json());
app.use(bodyParser.urlencoded({ extended: true })); 
app.use(expressValidator()); 
app.use(cookieParser());
app.use(session({ secret: 'SessionID' }));
app.use(passport.initialize());
app.use(passport.session());
app.use(flash());



mongoose.Promise = global.Promise;

mongoose.connect("mongodb://localhost:27017/new9_db");

var db = mongoose.connection;
db.on('error',console.error.bind(console,'connection error'));

var step1Schema=mongoose.Schema({
	'schoolname' : {type:String,required:[true,"{PATH} is required"],trim:true},
	'address' : {type:String , required:[true,"{PATH} is required"] , trim:true},
	'contact' : {type:Number , required:[true,"{PATH} is required"] , trim:true},
	'site' : {type:String , required:[true,"{PATH} is required"] , trim:true},
	'fname' : {type:String , required:[true,"{PATH} is required"] , trim:true},
	'pname' : {type:String , required:[true,"{PATH} is required"] , trim:true},
	'email' : {type:String , required:[true,"{PATH} is required"] , trim:true},
	'board' : {type:String , required:[true,"{PATH} is required"] , trim:true},
	'numteachers' : {type:Number , required:[true,"{PATH} is required"] , trim:true},
	'numgirls' : {type:Number , required:[true,"{PATH} is required"] , trim:true},
	'numboys' : {type:Number , required:[true,"{PATH} is required"] , trim:true},
	'user'  : {type:mongoose.Schema.Types.ObjectId, ref:'User'}

});
var step2Schema=mongoose.Schema({
	'thetext1' : {type:String,required:[true,"{PATH} is required"],trim:true},
	'thetext2' : {type:String , required:[true,"{PATH} is required"] , trim:true},
	'thetext3' : {type:String , required:[true,"{PATH} is required"] , trim:true},
	'thetext4' : {type:String , required:[true,"{PATH} is required"] , trim:true},
	'thetext5' : {type:String , required:[true,"{PATH} is required"] , trim:true},
	'thetext6' : {type:String , required:[true,"{PATH} is required"] , trim:true},
	'thetext7' : {type:String , required:[true,"{PATH} is required"] , trim:true},
	'thetext8' : {type:String , required:[true,"{PATH} is required"] , trim:true},
	'thetext9' : {type:String , required:[true,"{PATH} is required"] , trim:true},
	'thetext10' : {type:String , required:[true,"{PATH} is required"] , trim:true},
	'user'  : {type:mongoose.Schema.Types.ObjectId, ref:'User'}

	
});
var step3Schema=mongoose.Schema({
	'thetext1' : {type:String,required:[true,"{PATH} is required"],trim:true},
	'thetext2' : {type:String , required:[true,"{PATH} is required"] , trim:true},
	'thetext3' : {type:String , required:[true,"{PATH} is required"] , trim:true},
	'thetext4' : {type:String , required:[true,"{PATH} is required"] , trim:true},
	'thetext5' : {type:String , required:[true,"{PATH} is required"] , trim:true},
	'thetext6' : {type:String , required:[true,"{PATH} is required"] , trim:true},
	'thetext7' : {type:String , required:[true,"{PATH} is required"] , trim:true},
	'thetext8' : {type:String , required:[true,"{PATH} is required"] , trim:true},
	'thetext9' : {type:String , required:[true,"{PATH} is required"] , trim:true},
	'thetext10' : {type:String , required:[true,"{PATH} is required"] , trim:true},
	'user'  : {type:mongoose.Schema.Types.ObjectId, ref:'User'}

	
});
var step4Schema=mongoose.Schema({
	'thetext1' : {type:String,required:[true,"{PATH} is required"],trim:true},
	'thetext2' : {type:String , required:[true,"{PATH} is required"] , trim:true},
	'thetext3' : {type:String , required:[true,"{PATH} is required"] , trim:true},
	'thetext4' : {type:String , required:[true,"{PATH} is required"] , trim:true},
	'thetext5' : {type:String , required:[true,"{PATH} is required"] , trim:true},
	'thetext6' : {type:String , required:[true,"{PATH} is required"] , trim:true},
	'thetext7' : {type:String , required:[true,"{PATH} is required"] , trim:true},
	'thetext8' : {type:String , required:[true,"{PATH} is required"] , trim:true},
	'thetext9' : {type:String , required:[true,"{PATH} is required"] , trim:true},
	'thetext10' : {type:String , required:[true,"{PATH} is required"] , trim:true},
	'user'  : {type:mongoose.Schema.Types.ObjectId, ref:'User'}


});
var step5Schema=mongoose.Schema({
	'thetext1' : {type:String,required:[true,"{PATH} is required"],trim:true},
	'thetext2' : {type:String , required:[true,"{PATH} is required"] , trim:true},
	'thetext3' : {type:String , required:[true,"{PATH} is required"] , trim:true},
	'thetext4' : {type:String , required:[true,"{PATH} is required"] , trim:true},
	'thetext5' : {type:String , required:[true,"{PATH} is required"] , trim:true},
	'thetext6' : {type:String , required:[true,"{PATH} is required"] , trim:true},
	'thetext7' : {type:String , required:[true,"{PATH} is required"] , trim:true},
	'thetext8' : {type:String , required:[true,"{PATH} is required"] , trim:true},
	'user'  : {type:mongoose.Schema.Types.ObjectId, ref:'User'}

		
});
var step6Schema=mongoose.Schema({
	'thetext1' : {type:String,required:[true,"{PATH} is required"],trim:true},
	'thetext2' : {type:String , required:[true,"{PATH} is required"] , trim:true},
	'thetext3' : {type:String , required:[true,"{PATH} is required"] , trim:true},
	'user'  : {type:mongoose.Schema.Types.ObjectId, ref:'User'}

});
var step7Schema=mongoose.Schema({
	'thetext1' : {type:String,required:[true,"{PATH} is required"],trim:true},
	'thetext2' : {type:String , required:[true,"{PATH} is required"] , trim:true},
	'thetext3' : {type:String , required:[true,"{PATH} is required"] , trim:true},
	'thetext4' : {type:String , required:[true,"{PATH} is required"] , trim:true},
	'thetext5' : {type:String , required:[true,"{PATH} is required"] , trim:true},
	'thetext6' : {type:String , required:[true,"{PATH} is required"] , trim:true},
	'thetext7' : {type:String , required:[true,"{PATH} is required"] , trim:true},
	'thetext8' : {type:String , required:[true,"{PATH} is required"] , trim:true},
	'thetext9' : {type:String , required:[true,"{PATH} is required"] , trim:true},
	'thetext10' : {type:String , required:[true,"{PATH} is required"] , trim:true},
	'user'  : {type:mongoose.Schema.Types.ObjectId, ref:'User'}

	
});
var step8Schema=mongoose.Schema({
	'thetext1' : {type:String,required:[true,"{PATH} is required"],trim:true},
	'thetext2' : {type:String , required:[true,"{PATH} is required"] , trim:true},
	'thetext3' : {type:String , required:[true,"{PATH} is required"] , trim:true},
	'thetext4' : {type:String , required:[true,"{PATH} is required"] , trim:true},
	'thetext5' : {type:String , required:[true,"{PATH} is required"] , trim:true},
	'thetext6' : {type:String , required:[true,"{PATH} is required"] , trim:true},
	'thetext7' : {type:String , required:[true,"{PATH} is required"] , trim:true},
	'thetext8' : {type:String , required:[true,"{PATH} is required"] , trim:true},
	'thetext9' : {type:String , required:[true,"{PATH} is required"] , trim:true},
	'thetext10' : {type:String , required:[true,"{PATH} is required"] , trim:true},
	'user'  : {type:mongoose.Schema.Types.ObjectId, ref:'User'}

	
});
var step9Schema=mongoose.Schema({
	'thetext1' : {type:String,required:[true,"{PATH} is required"],trim:true},
	'thetext2' : {type:String , required:[true,"{PATH} is required"] , trim:true},
	'thetext3' : {type:String , required:[true,"{PATH} is required"] , trim:true},
	'thetext4' : {type:String , required:[true,"{PATH} is required"] , trim:true},
	'thetext5' : {type:String , required:[true,"{PATH} is required"] , trim:true},
	'thetext6' : {type:String , required:[true,"{PATH} is required"] , trim:true},
	'thetext7' : {type:String , required:[true,"{PATH} is required"] , trim:true},
	'user'  : {type:mongoose.Schema.Types.ObjectId, ref:'User'}

});
var step10Schema=mongoose.Schema({
	'thetext1' : {type:String,required:[true,"{PATH} is required"],trim:true},
	'thetext2' : {type:String , required:[true,"{PATH} is required"] , trim:true},
	'thetext3' : {type:String , required:[true,"{PATH} is required"] , trim:true},
	'thetext4' : {type:String , required:[true,"{PATH} is required"] , trim:true},
	'thetext5' : {type:String , required:[true,"{PATH} is required"] , trim:true},
	'thetext6' : {type:String , required:[true,"{PATH} is required"] , trim:true},
	'thetext7' : {type:String , required:[true,"{PATH} is required"] , trim:true},
	'thetext8' : {type:String , required:[true,"{PATH} is required"] , trim:true},
	'thetext9' : {type:String , required:[true,"{PATH} is required"] , trim:true},
	'thetext10' : {type:String , required:[true,"{PATH} is required"] , trim:true},
	'thetext11' : {type:String , required:[true,"{PATH} is required"] , trim:true},
	'user'  : {type:mongoose.Schema.Types.ObjectId, ref:'User'}

});

var userSchema = mongoose.Schema({
		
		username     : {type:String, required:[true,"{PATH} is required"],trim:true},
		
        password     : {type:String, required:[true,"{PATH} is required"],trim:true},
        confirmpassword     : {type:String},
        formstatus : {type:Number},
        paymentmode : {type:Boolean}
        

});

userSchema.methods.generateHash = function(password) {
    return bcrypt.hashSync(password, bcrypt.genSaltSync(8), null);
};


userSchema.methods.validPassword = function(password) {
    return bcrypt.compareSync(password, this.password);
};


var Step1 = mongoose.model('Step1',step1Schema);
var Step2 = mongoose.model('Step2',step2Schema);
var Step3 = mongoose.model('Step3',step3Schema);
var Step4 = mongoose.model('Step4',step4Schema);
var Step5 = mongoose.model('Step5',step5Schema);
var Step6 = mongoose.model('Step6',step6Schema);
var Step7 = mongoose.model('Step7',step7Schema);
var Step8 = mongoose.model('Step8',step8Schema);
var Step9 = mongoose.model('Step9',step9Schema);
var Step10 = mongoose.model('Step10',step10Schema);
var User = mongoose.model('User',userSchema);


passport.serializeUser(function(user, done) {
        done(null, user.id);
});

passport.deserializeUser(function(id, done) {
        User.findById(id, function(err, user) {
            done(err, user);
        });
});

passport.use('local-signup', new LocalStrategy({
        
        usernameField : 'username',
        passwordField : 'password',
        passReqToCallback : true
    },
    function(req, username, password, done) {
    	confirmpassword=req.body.confirmpassword;
    	formstatus=req.body.formstatus;
    	paymentmode=req.body.paymentmode;


        process.nextTick(function() {
        	if(password != confirmpassword) {
                return done(null, false, req.flash('signupMessage', 'Passwords do not match.'));
            }

        User.findOne({ 'username' :  username }, function(err, user) {
            if (err)
                return done(err);

            if (user) {
                return done(null, false, req.flash('signupMessage', 'That username is already taken.'));
            } else {

                var newUser = new User();

                // set the user's local credentials
                
                newUser.username = username;
                newUser.formstatus    = formstatus;
                newUser.paymentmode    = paymentmode;

                newUser.password = newUser.generateHash(password);

                // save the user
                newUser.save(function(err) {
                    if (err){
                    	console.log(err);
                    }
                       
                    return done(null, newUser);
                });
            }

        });    

        });

    }));




passport.use('local-login', new LocalStrategy({
        // by default, local strategy uses username and password, we will override with email
        usernameField : 'username',
        passwordField : 'password',
        passReqToCallback : true // allows us to pass back the entire request to the callback
    },
    function(req, username, password, done) { // callback with email and password from our form

        // find a user whose email is the same as the forms email
        // we are checking to see if the user trying to login already exists
        User.findOne({ 'username' :  username }, function(err, user) {
            // if there are any errors, return the error before anything else
            if (err)
                return done(err);

            // if no user is found, return the message
            if (!user)
                return done(null, false, req.flash('loginMessage', 'No user found.')); // req.flash is the way to set flashdata using connect-flash

            // if the user is found but the password is wrong
            if (!user.validPassword(password))
                return done(null, false, req.flash('loginMessage', 'Oops! Wrong password.')); // create the loginMessage and save it to session as flashdata

            // all is well, return successful user
            return done(null, user);
        });

    }));


app.get('/', function(req, res){

	if(req.isAuthenticated()){
		user=req.user;
		res.render("home.pug", {user:user});
	}
	else{
		res.render("unindex.pug");
	}
});

app.get('/step-1', function(req,res){
	if(req.isAuthenticated()){
		user=req.user;
		res.render("step-1.pug", {user:user});
	}
	else{
		res.send("You need to be logged in to view this.");
	}

});

app.post('/step-1', function(){
	user=req.user;

	var data = new Step1({
		schoolname : req.body.schoolname,
		address : req.body.address,
		contact : req.body.contact,
		site : req.body.site,
		fname : req.body.fname,
		pname : req.body.pname,
		email : req.body.email,
		board : req.body.board,
		numteachers : req.body.numteachers,
		numboys : req.body.numboys,
		numgirls : req.body.numgirls,
		user : req.user._id

		
	});

	data.save(function(err){
		if(err){
			console.log(err);
			res.render('step-1.pug', {error : err, data : data, user : user});
		}
		else{
			console.log('Data saved');
			res.redirect('/step-2');
		}
	});
});



app.get('/step-2', function(req,res){
	if(req.isAuthenticated()){
		user=req.user;
		res.render("step-2.pug", {user:user});
	}
	else{
		res.send("You need to be logged in to view this.");
	}

});

app.post('/step-2', function(){
	user=req.user;

	var data = new Step2({
		thetext1 : req.body.thetext1,
		thetext2 : req.body.thetext2,
		thetext3 : req.body.thetext3,
		thetext4 : req.body.thetext4,
		thetext5 : req.body.thetext5,
		thetext6 : req.body.thetext6,
		thetext7 : req.body.thetext7,
		thetext8 : req.body.thetext8,
		thetext9 : req.body.thetext9,
		thetext10 : req.body.thetext10,
		user : req.user._id


		
	});

	data.save(function(err){
		if(err){
			console.log(err);
			res.render('step-2.pug', {error : err, data : data, user : user});
		}
		else{
			console.log('Data saved');
			res.redirect('/step-3');
		}
	});
});


app.get('/step-3', function(req,res){
	if(req.isAuthenticated()){
		user=req.user;
		res.render("step-3.pug", {user:user});
	}
	else{
		res.send("You need to be logged in to view this.");
	}

});

app.post('/step-3', function(){
	user=req.user;

	var data = new Step3({
		thetext1 : req.body.thetext1,
		thetext2 : req.body.thetext2,
		thetext3 : req.body.thetext3,
		thetext4 : req.body.thetext4,
		thetext5 : req.body.thetext5,
		thetext6 : req.body.thetext6,
		thetext7 : req.body.thetext7,
		thetext8 : req.body.thetext8,
		thetext9 : req.body.thetext9,
		thetext10 : req.body.thetext10,
		user : req.user._id


		
	});

	data.save(function(err){
		if(err){
			console.log(err);
			res.render('step-3.pug', {error : err, data : data, user : user});
		}
		else{
			console.log('Data saved');
			res.redirect('/step-4');
		}
	});
});


app.get('/step-4', function(req,res){
	if(req.isAuthenticated()){
		user=req.user;
		res.render("step-4.pug", {user:user});
	}
	else{
		res.send("You need to be logged in to view this.");
	}

});

app.post('/step-4', function(){
	user=req.user;

	var data = new Step4({
		thetext1 : req.body.thetext1,
		thetext2 : req.body.thetext2,
		thetext3 : req.body.thetext3,
		thetext4 : req.body.thetext4,
		thetext5 : req.body.thetext5,
		thetext6 : req.body.thetext6,
		thetext7 : req.body.thetext7,
		thetext8 : req.body.thetext8,
		thetext9 : req.body.thetext9,
		thetext10 : req.body.thetext10,
		user : req.user._id


		
	});

	data.save(function(err){
		if(err){
			console.log(err);
			res.render('step-4.pug', {error : err, data : data, user : user});
		}
		else{
			console.log('Data saved');
			res.redirect('/step-5');
		}
	});
});


app.get('/step-5', function(req,res){
	if(req.isAuthenticated()){
		user=req.user;
		res.render("step-5.pug", {user:user});
	}
	else{
		res.send("You need to be logged in to view this.");
	}

});

app.post('/step-5', function(){
	user=req.user;

	var data = new Step5({
		thetext1 : req.body.thetext1,
		thetext2 : req.body.thetext2,
		thetext3 : req.body.thetext3,
		thetext4 : req.body.thetext4,
		thetext5 : req.body.thetext5,
		thetext6 : req.body.thetext6,
		thetext7 : req.body.thetext7,
		thetext8 : req.body.thetext8,
		user : req.user._id

			
	});

	data.save(function(err){
		if(err){
			console.log(err);
			res.render('step-5.pug', {error : err, data : data, user : user});
		}
		else{
			console.log('Data saved');
			res.redirect('/step-6');
		}
	});
});


app.get('/step-6', function(req,res){
	if(req.isAuthenticated()){
		user=req.user;
		res.render("step-6.pug", {user:user});
	}
	else{
		res.send("You need to be logged in to view this.");
	}

});

app.post('/step-6', function(){
	user=req.user;

	var data = new Step6({
		thetext1 : req.body.thetext1,
		thetext2 : req.body.thetext2,
		thetext3 : req.body.thetext3,
		user : req.user._id

				
	});

	data.save(function(err){
		if(err){
			console.log(err);
			res.render('step-6.pug', {error : err, data : data, user : user});
		}
		else{
			console.log('Data saved');
			res.redirect('/step-7');
		}
	});
});


app.get('/step-7', function(req,res){
	if(req.isAuthenticated()){
		user=req.user;
		res.render("step-7.pug", {user:user});
	}
	else{
		res.send("You need to be logged in to view this.");
	}

});

app.post('/step-7', function(){
	user=req.user;

	var data = new Step7({
		thetext1 : req.body.thetext1,
		thetext2 : req.body.thetext2,
		thetext3 : req.body.thetext3,
		thetext4 : req.body.thetext4,
		thetext5 : req.body.thetext5,
		thetext6 : req.body.thetext6,
		thetext7 : req.body.thetext7,
		thetext8 : req.body.thetext8,
		thetext9 : req.body.thetext9,
		thetext10 : req.body.thetext10,
		user : req.user._id


		
	});

	data.save(function(err){
		if(err){
			console.log(err);
			res.render('step-7.pug', {error : err, data : data, user : user});
		}
		else{
			console.log('Data saved');
			res.redirect('/step-8');
		}
	});
});


app.get('/step-8', function(req,res){
	if(req.isAuthenticated()){
		user=req.user;
		res.render("step-8.pug", {user:user});
	}
	else{
		res.send("You need to be logged in to view this.");
	}

});

app.post('/step-8', function(){
	user=req.user;

	var data = new Step8({
		thetext1 : req.body.thetext1,
		thetext2 : req.body.thetext2,
		thetext3 : req.body.thetext3,
		thetext4 : req.body.thetext4,
		thetext5 : req.body.thetext5,
		thetext6 : req.body.thetext6,
		thetext7 : req.body.thetext7,
		thetext8 : req.body.thetext8,
		thetext9 : req.body.thetext9,
		thetext10 : req.body.thetext10,
		user : req.user._id


		
	});

	data.save(function(err){
		if(err){
			console.log(err);
			res.render('step-8.pug', {error : err, data : data, user : user});
		}
		else{
			console.log('Data saved');
			res.redirect('/step-9');
		}
	});
});


app.get('/step-9', function(req,res){
	if(req.isAuthenticated()){
		user=req.user;
		res.render("step-9.pug", {user:user});
	}
	else{
		res.send("You need to be logged in to view this.");
	}

});

app.post('/step-9', function(){
	user=req.user;

	var data = new Step9({
		thetext1 : req.body.thetext1,
		thetext2 : req.body.thetext2,
		thetext3 : req.body.thetext3,
		thetext4 : req.body.thetext4,
		thetext5 : req.body.thetext5,
		thetext6 : req.body.thetext6,
		thetext7 : req.body.thetext7,
		user : req.user._id

				
	});

	data.save(function(err){
		if(err){
			console.log(err);
			res.render('step-9.pug', {error : err, data : data, user : user});
		}
		else{
			console.log('Data saved');
			res.redirect('/step-10');
		}
	});
});


app.get('/step-10', function(req,res){
	if(req.isAuthenticated()){
		user=req.user;
		res.render("step-10.pug", {user:user});
	}
	else{
		res.send("You need to be logged in to view this.");
	}

});

app.post('/step-10', function(){
	user=req.user;

	var data = new Step10({
		thetext1 : req.body.thetext1,
		thetext2 : req.body.thetext2,
		thetext3 : req.body.thetext3,
		thetext4 : req.body.thetext4,
		thetext5 : req.body.thetext5,
		thetext6 : req.body.thetext6,
		thetext7 : req.body.thetext7,
		thetext8 : req.body.thetext8,
		thetext9 : req.body.thetext9,
		thetext10 : req.body.thetext10,
		thetext11 : req.body.thetext11,
		user : req.user._id
		


		
	});

	data.save(function(err){
		if(err){
			console.log(err);
			res.render('step-10.pug', {error : err, data : data, user : user});
		}
		else{
			console.log('Data saved');
			res.redirect('/');
		}
	});
});

app.get('/awards', function(req, res){
	if(req.isAuthenticated()){
		user=req.user;
		res.render('awards.pug', {user:user});
	}
	else{
		res.send("You need to be logged in to view this");
	}

});

app.get('/panel', function(req, res){
	if(req.isAuthenticated()){
		user=req.user;
		res.render('panel.pug', {user:user});
	}
	else{
		res.send("You need to be logged in to view this");
	}

});

app.get('/contact', function(req, res){
	if(req.isAuthenticated()){
		user=req.user;
		res.render('contact.pug', {user:user});
	}
	else{
		res.send("You need to be logged in to view this");
	}

});

app.get('/about', function(req, res){
	if(req.isAuthenticated()){
		user=req.user;
		res.render('about.pug', {user:user});
	}
	else{
		res.send("You need to be logged in to view this");
	}

});


app.get('/login', function(req,res){
    res.render('login.pug', { message: req.flash('loginMessage') }); 
});

app.post('/login', passport.authenticate('local-login', {
    successRedirect : '/', // redirect to the secure profile section
    failureRedirect : '/login', // redirect back to the signup page if there is an error
    failureFlash : true // allow flash messages
}));


app.get('/signup', function(req,res){
    res.render('signup.pug', { message: req.flash('signupMessage') });
});

app.post('/signup', passport.authenticate('local-signup', {
    successRedirect : '/', // redirect to the secure profile section
    failureRedirect : '/signup', // redirect back to the signup page if there is an error
    failureFlash : true // allow flash messages
}));


app.get('/logout', function(req, res) {
    req.logout();
    res.redirect('/');
});


app.get('*', function(req,res){
	res.status(404).send(`Oops! Error 404, Page not found. Go to <a href="/">home</a> page`);
});

app.listen(process.env.PORT || 3000);

	

