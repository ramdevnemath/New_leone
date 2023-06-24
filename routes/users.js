const userController = require('../controllers/userControllers')
const cartController = require('../controllers/cartController')
const orderController = require('../controllers/orderControllers')
const couponController = require('../controllers/couponControllers')
const productController = require('../controllers/productControllers')
const otplib = require('otplib')
var express = require('express')
var router = express.Router()


//get leone user pages
router.get('/', userController.homePage)
router.get('/index', verify, userController.indexPage)
router.get('/login', userauth, userController.loginPage)
router.post('/login', userauth, userController.postLogin)
router.get('/signup', userauth, userController.userSignup)
router.post('/signup', userauth, userController.postSignup)
router.get('/logout', verify, userController.logout)
router.get('/single-product/:id', userController.userSingleProduct)
router.get('/mens', userController.mensPage)
router.get('/womens', userController.womensPage)
router.get('/kids', userController.kidsPage)
router.post("/filterproducts",userController.filterProducts)
//otp route
router.get('/otp', (req, res) => {
    res.render('users/otp', {other:true})
})
router.post('/sendotp', userController.sendOtp);
router.post('/otp', userController.otpLogin)
router.post('/verifyotp', userController.verifyOtp)

//cart control
router.get('/addtoCart/:id', cartController.cartCount, cartController.addtoCart) 
router.get('/cart', cartController.cartCount, cartController.getCartProducts)
router.post('/changeProductQuantity', cartController.changeProductQuantity)
router.post('/removeItem', cartController.removeItem)
router.get('/product-size-selector', cartController.productSizeSelector)
router.get('/getCartTotals' , cartController.getCartTotals)

//verify route
router.get('/checkLogin', cartController.checkLogin)
router.post('/emailexists', userController.emailVerify)

// Proceed to checkout
router.get('/address', userController.isLogin, userController.savedAddressget)
router.post('/address', userController.placeOrderPost)
router.get('/savedAddress', userController.isLogin, cartController.cartCount, userController.deliveryAddress)
router.post('/savedAddress', userController.savedAddressPost)
router.get('/editSavedAddress/:id', cartController.cartCount, userController.editSavedAddress)
router.post('/editSavedAddress/:id', userController.editSavedAddressPost)
router.delete('/deleteAddress/:id', userController.deleteAddress)

//order controller
router.get('/orderPlaced', orderController.orderPlacedCod)
router.get('/Orders', userController.isLogin, cartController.cartCount, orderController.orders)
router.post('/orders/date', orderController.sortOrders)
router.get('/cancel-order/', userController.isLogin, orderController.cancelOrder)
router.get('/return-order/', userController.isLogin, orderController.returnOrder)
router.get('/order-not-shipped', userController.isLogin, orderController.listOfNotShippedOrder)
router.get('/order-cancelled-list', userController.isLogin, orderController.listOfCancelledOrder)
router.get('/order-returned-list', userController.isLogin, orderController.listOfReturnedOrder)
router.get('/invoice/', userController.isLogin, orderController.invoice)

//coupon controller
router.post('/apply-coupon',couponController.applyCoupon)

//payment controller
router.post('/verify-payment', userController.paymentVerify)
router.get('/payment-failed', userController.paymentFailed)

//Profile
router.get('/profile', userController.isLogin, cartController.cartCount, userController.userProfile)
router.patch('/profile/:id', userController.editUserProfile)
router.patch('/addressEdit', userController.addressEdit)
router.post('/update-user-password', userController.confirmAndUpdatePassword)

//Search control
// router.get('/shop/search/suggestions/',userController.search)
// router.get('/search',userController.searching)
router.get('/api/search', productController.searchProduct)
  

//middleware for preventing loading for strangers
function userauth(req, res, next) {
    if (req.session && req.session.user && req.session.userloggedIn) {
        res.redirect("/index")
    } else {
        next()
    }
}
function verify(req, res, next) {
    if (req.session && req.session.user && req.session.userloggedIn) {
        next();
    } else {
        res.redirect("/login")
    }
}

module.exports = router;