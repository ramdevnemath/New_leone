const Order = require("../models/orderSchema");
const Wallet = require('../models/walletSchema')
const mongoose = require('mongoose');
const ObjectId = mongoose.Types.ObjectId;

exports.orderPlacedCod = (req, res) => {
  let user = req.session.user;

  try {
    res.render("users/orderPlacedCod", { user, cartIcon: true });
  } catch (error) {
    console.log(error);
    res.status(500).send("Internal Server Error");
  }
};

exports.orders = async (req, res) => {
  let orders = await Order.find({ userId: req.session.user._id })
    .sort("updatedAt")
    .populate({
      path: "products.item",
      model: "Product",
    })
    .exec();

  const cartCount = req.cartCount;
  if (req.session.filterOrders) {
    res.locals.orders = req.session.filterOrders;
    req.session.filterOrders = null;
  } else if (req.session.noOrders) {
    res.locals.orders = req.session.noOrders;
    req.session.noOrders = null;
  } else if (req.session.cancelledOrders) {
    res.locals.orders = req.session.cancelledOrders;
    req.session.cancelledOrders = null;
  } else if (req.session.notShippedOrders) {
    res.locals.orders = req.session.notShippedOrders;
    req.session.notShippedOrders = null;
  } else if (req.session.returneddOrders) {
    res.locals.orders = req.session.returneddOrders;
    req.session.returneddOrders = null;
  } else {
    res.locals.orders = orders;
  }
  res.render("users/orderView", {
    footer: false,
    cartCount,
    user: req.session.user,
  });
};

exports.viewOrderProducts = async (req, res) => {
  try {
    const orderId = req.params.id;
    const order = await Order.findById(orderId)
      .populate({
        path: "products.item",
        model: "Product",
      })
      .exec();

    if (!order) {
      return res.status(404).send("Order not found");
    }

    const orderedProducts = order.products.map((product) => {
      return {
        product: product.item,
        quantity: product.quantity,
      };
    });

    res.render("users/viewProductDetails", {
      footer: false,
      user: req.session.user,
      order,
      orderedProducts,
    });

  } catch (error) {
    console.log(error);
    res.status(500).send("Internal server error");
  }
};

exports.cancelOrder = async (req, res) => {
  // Retrieve the necessary parameters from the query
  let productId = req.query.productId;
  let orderId = req.query.orderId;
  // let reason = req.query.reason;

  // Retrieve the order and populate the products
  let orders = await Order.find({ _id: orderId })
    .populate({
      path: "products.item",
      model: "Product",
    })
    .exec();

  let product = null;
  for (let i = 0; i < orders.length; i++) {
    let order = orders[i];
    product = order.products.find(
      (product) => product.item._id.toString() === productId
    );

    if (product) {
      product.orderstatus = "cancelled";
      product.deliverystatus = "cancelled";

      if (order.paymentMethod == "RazorPay") {
        // Add the product price to the wallet balance
        let wallet = await Wallet.findOne({ userId: order.userId });

        if (!wallet) {
          wallet = new Wallet({
            userId: order.userId,
            balance: 0, // Set the initial balance to 0 or any other desired value
          });
        }

        let price = product.currentPrice;
        price += Math.floor(price * 0.12);
        wallet.balance += price;

        await wallet.save();
      }

      await order.save();
      break;
    }
  }
  res.redirect("/orders");
};

exports.returnOrder = async (req, res) => {
  // Retrieve the necessary parameters from the query
  let productId = req.query.productId;
  let orderId = req.query.orderId;

  // Retrieve the order and populate the products
  let orders = await Order.find({ _id: orderId })
    .populate({
      path: "products.item",
      model: "Product",
    })
    .exec();

  let product = null;
  for (let i = 0; i < orders.length; i++) {
    let order = orders[i];
    product = order.products.find(
      (product) => product.item._id.toString() === productId
    );
    if (product) {
      product.orderstatus = "returned";
      product.deliverystatus = "returned";

      
      if (order.paymentMethod == "RazorPay") {
        // Add the product price to the wallet balance
        let wallet = await Wallet.findOne({ userId: order.userId });
        if (!wallet) {
          wallet = new Wallet({
            userId: order.userId,
            balance: 0, // Set the initial balance to 0 or any other desired value
          });
        }

        let price = product.currentPrice;
        price += Math.floor(price * 0.12);
        wallet.balance += price;

        await wallet.save();
      }

      await order.save();
      break;
    }
  }

  res.redirect("/orders");
};


exports.sortOrders = async (req, res) => {
  const userId = req.session.user._id;
  const selectedYear = req.body.selector;

  const startDate = new Date(selectedYear, 0, 1); // January 1st of selected year
  const endDate = new Date(selectedYear, 11, 31, 23, 59, 59, 999); // December 31st of selected year

  // Find all orders of the user that were created between the start and end dates of the selected year
  const orders = await Order.find({
    userId: userId,
    createdAt: { $gte: startDate, $lte: endDate }
  }).populate({
    path: 'products.item',
    model: 'Product'
  }).exec();
  if (orders) {
    req.session.filterOrders = orders
    console.log("got 2023")
  } else {
    req.session.noOrders = 'no item founded'
    console.log("got null")
  }
  res.redirect('/orders')
}

exports.listOfNotShippedOrder = async (req, res) => {
  let orders = await Order.find({
    userId: req.session.user._id,
    'products.deliverystatus': 'not-shipped',
    'products.orderstatus': 'processing'

  }).populate({
    path: 'products.item',
    model: 'Product'
  }).exec();

  req.session.notShippedOrders = orders
  res.redirect('/orders')
}

exports.listOfCancelledOrder = async (req, res) => {
  let orders = await Order.find({
    userId: req.session.user._id,
    'products.orderstatus': 'cancelled'
  }).populate({
    path: 'products.item',
    model: 'Product'
  }).exec();

  req.session.cancelledOrders = orders
  res.redirect('/orders')

}

exports.listOfReturnedOrder = async (req, res) => {

  let orders = await Order.find({
    userId: req.session.user._id,
    'products.orderstatus': 'returned'
  }).populate({
    path: 'products.item',
    model: 'Product'
  }).exec();

  req.session.returneddOrders = orders
  res.redirect('/orders')

}

exports.invoice = async (req, res) => {

  let productId = req.query.productId
  let orderId = req.query.orderId;

  let orders = await Order.find({ _id: orderId })
    .populate({
      path: 'products.item',
      model: 'Product'
    }).exec();

  let product = null;
  for (let i = 0; i < orders.length; i++) {
    let order = orders[i];
    product = order.products.find(product => product.item._id.toString() === productId);
    if (product) {
      // If product found, fetch the details from the Product model
      break; // Exit the loop once product is found
    }
  }
  res.render('users/invoice', { orders, product, user: req.session.user });
}