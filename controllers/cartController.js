const Cart = require("../models/cartSchema");
const mongoose = require('mongoose');
const User = require("../models/userSchema");
const ObjectId = mongoose.Types.ObjectId;
const Product = require("../models/productSchema");
// const bcrypt = require("bcrypt");
// const { response } = require("../app");
// const flash = require("connect-flash");
// const { success } = require("toastr");
// const { json } = require("body-parser");


exports.addtoCart = async (req, res) => {
  const productId = new ObjectId(req.params.id);
  const userId = req.session.user._id; // we will get user id here
  let addedProduct = await Product.findOne({ _id: req.params.id });
  let taxAmount = Math.floor((addedProduct.price / 100) * 12);
  const offerPrice = req.query.discount;
  let proPrice = await Product.findOne({ _id: req.params.id });

  console.log("worked");
  try {
    const quantity = 1;
    let proObj = {
      item: productId,
      quantity: quantity,
      currentPrice: req.query.discount !=0 ? offerPrice : proPrice.price,
      stock: addedProduct.stock,
      tax: taxAmount,
      size: req.query.size,
      deliverystatus: "not-shipped",
      orderstatus: "processing",
    };
    let userCart = await Cart.findOne({ userId: new ObjectId(userId) });
    let cartCheckProId = req.params.id;
    if (userCart) {
      let proExist = userCart.products.findIndex(
        (product) =>
          product.item == cartCheckProId && product.size === req.query.size
      );
      if (proExist > -1) {
        await Cart.updateOne(
          { userId, "products.item": productId, "products.size": req.query.size },
          { $inc: { "products.$.quantity": 1 } }
        );
      } else {
        await Cart.updateOne({ userId }, { $push: { products: proObj } });
      }
    } else {
      const cartObj = new Cart({
        userId: userId,
        products: [proObj],
      });
      await Cart.create(cartObj);
    }
    console.log("working");
    res.json(true);
  } catch (error) {
    console.error(error);
    res.status(500).send("Internal server error");
  }
};

exports.cartCount = async (req, res, next) => {
  try {

    let user = req.session.user;

    let cartCount = 0;
    if (user) {

      const cart = await Cart.findOne({ userId: user._id }); // Await the query to get the cart object

      if (cart) {
        // Replace cart.products.length with cart.products.reduce((acc, product) => acc + product.quantity, 0)
        cartCount = cart.products.reduce(
          (acc, product) => acc + product.quantity,
          0
        );
      }
    }
    req.cartCount = cartCount;
    next();
  } catch (error) {
    console.log(error);
  }
};

exports.productSizeSelector = async (req, res) => {
  let proId = req.query.proId;
  if (req.session.user) {
    let cartItem = await Cart.findOne({
      user: req.session.user._id,
      products: {
        $elemMatch: {
          size: req.params.id,
          item: proId
        }
      }
    });
    if (cartItem) {
      return res.json(true)
    } else {
      return res.json(false)
    }
  } else {
    res.redirect('/login')
  }

}

exports.getCartProducts = async (req, res) => {
  let user = req.session.user;
  if (!user) {
    res.redirect('/login')
  } else {
    let userId = req.session.user._id;
    userId = userId.toString();
    let cartItems = [];

    try {
      cartItems = await Cart.aggregate([
        {
          $match: { userId },
        },
        {
          $unwind: "$products",
        },
        {
          $project: {
            item: { $toObjectId: "$products.item" },
            quantity: "$products.quantity",
            size: "$products.size",
            currentPrice: "$products.currentPrice",
            tax: "$products.tax",
            unique_id: "$products._id",
          },
        },
        {
          $lookup: {
            from: "products",
            localField: "item",
            foreignField: "_id",
            as: "productInfo",
          },
        },
        {
          $project: {
            unique_id: 1,
            item: 1,
            quantity: 1,
            size: 1,
            currentPrice: 1,
            tax: 1,
            productInfo: { $arrayElemAt: ["$productInfo", 0] },
          },
        },
      ]);

      let total = await Cart.aggregate([
        {
          $match: { userId },
        },
        {
          $unwind: "$products",
        },
        {
          $project: {
            item: { $toObjectId: "$products.item" },
            quantity: "$products.quantity",
            size: "$products.size",
            currentPrice: "$products.currentPrice",
            tax: "$products.tax",
          },
        },
        {
          $lookup: {
            from: "products",
            localField: "item",
            foreignField: "_id",
            as: "productInfo",
          },
        },
        {
          $project: {
            item: 1,
            quantity: 1,
            size: 1,
            currentPrice: 1,
            tax: 1,
            productInfo: { $arrayElemAt: ["$productInfo", 0] },
          },
        },
        {
          $group: {
            _id: null,
            totalTax: { $sum: { $multiply: ["$quantity", "$tax"] } },
            total: { $sum: { $multiply: ["$quantity", "$currentPrice"] } },
            totalWithTax: {
              $sum: {
                $multiply: ["$quantity", { $add: ["$tax", "$currentPrice"] }],
              },
            },
            // total: { $sum: { $multiply: ["$quantity", "$productInfo.price"] } },
          },
        },
      ]);
      let subtotal = 0;
      let tax = 0;
      let totalWithTax = 0;
      if (total.length > 0) {
        subtotal = total[0].total;
        tax = total[0].totalTax;
        totalWithTax = total[0].totalWithTax;
      }


      const cartCount = req.cartCount;

      res.render("users/cart", {
        cartItems,
        user,
        cartCount,
        cartIcon: true,
        total,
        subtotal,
        tax,
        totalWithTax,
        // result,
      });
    } catch (error) {
      console.log(error);
    }
  }
};

exports.changeProductQuantity = async (req, res) => {

  try {
    const response = {};
    let cart = req.body.cart;
    let count = req.body.count;
    let quantity = req.body.quantity;
    let unique_id = new ObjectId(req.body.product);
    count = parseInt(count);
    quantity = parseInt(quantity);

    if (count == -1 && quantity == 1) {
      await Cart.updateOne(
        {
          _id: req.body.cart,
          "products._id": unique_id,
        },
        {
          $pull: { products: { _id: unique_id } },
        }
      );

      res.json({ removeProduct: true });
    } else {
      await Cart.updateOne(
        { _id: req.body.cart, "products._id": unique_id },
        { $inc: { "products.$.quantity": count } }
      );
      let user = req.session.user;
      
      let total = await Cart.aggregate([
        {
          $match: { userId : req.session.user._id },
        },
        {
          $unwind: "$products",
        },
        {
          $project: {
            item: { $toObjectId: "$products.item" },
            quantity: "$products.quantity",
            size: "$products.size",
            currentPrice: "$products.currentPrice",
            tax: "$products.tax",
          },
        },
        {
          $lookup: {
            from: "products",
            localField: "item",
            foreignField: "_id",
            as: "productInfo",
          },
        },
        {
          $project: {
            item: 1,
            quantity: 1,
            size: 1,
            currentPrice: 1,
            tax: 1,
            productInfo: { $arrayElemAt: ["$productInfo", 0] },
          },
        },
        {
          $group: {
            _id: null,
            totalTax: { $sum: { $multiply: ["$quantity", "$tax"] } },
            total: { $sum: { $multiply: ["$quantity", "$currentPrice"] } },
            totalWithTax: {
              $sum: {
                $multiply: ["$quantity", { $add: ["$tax", "$currentPrice"] }],
              },
            },
            // total: { $sum: { $multiply: ["$quantity", "$productInfo.price"] } },
          },
        },
      ]);
      // response.status = true;
      res.json({ success: true, total });
      console.log("else worked");
    }

  } catch (error) {
    console.error(error);
  }
};


exports.removeItem = async (req, res) => {
  try {
    let unique_id = new ObjectId(req.body.product);
    await Cart.updateOne(
      {
        _id: req.body.cart,
        "products._id": unique_id,
      },
      {
        $pull: { products: { _id: unique_id } },
      }
    );
    let displayTotal = await Cart.aggregate([
      {
        $match: { user: req.session.userId },
      },
      {
        $unwind: "$products",
      },
      {
        $project: {
          item: { $toObjectId: "$products.item" },
          size: "$products.size",
          currentPrice: "$products.currentPrice",
          tax: "$products.tax",
          quantity: "$products.quantity",
        },
      },
      {
        $lookup: {
          from: "products",
          localField: "item",
          foreignField: "_id",
          as: "productInfo",
        },
      },
      {
        $project: {
          item: 1,
          size: 1,
          currentPrice: 1,
          tax: 1,
          quantity: 1,
          productInfo: { $arrayElemAt: ["$productInfo", 0] },
        },
      },
      {
        $group: {
          _id: null,

          totalTax: { $sum: { $multiply: ["$quantity", "$tax"] } },
          total: { $sum: { $multiply: ["$quantity", "$currentPrice"] } },
          totalWithTax: {
            $sum: {
              $multiply: ["$quantity", { $add: ["$tax", "$currentPrice"] }],
            },
          },
        },
      },
    ]);

    let response = {};
    if (displayTotal.length === 0) {

      response.subtotal = 0;
      response.tax = 0;
      response.totalWithTax = 0;
      await res.json(response);
    } else {
      let subtotal = displayTotal[0].total;
      let tax = displayTotal[0].totalTax;
      let totalWithTax = displayTotal[0].totalWithTax;

      response.subtotal = subtotal;
      response.tax = tax;
      response.totalWithTax = totalWithTax;

      await res.json(response);
    }
  } catch (error) {
    console.log(error);
  }
};

exports.checkLogin = async (req, res) => {
  if (req.session.user) {
    // User is logged in
    res.status(200).json({
      loggedIn: true
    });
  } else {
    // User is not logged in
    res.json({
      loggedIn: false
    });
  }
}

exports.getCartTotals = async (req, res) => {
  try {
    const totals = await Cart.aggregate([
      {
        $match: { user: req.session.userId },
      },
      {
        $unwind: "$products",
      },
      {
        $project: {
          quantity: "$products.quantity",
          currentPrice: "$products.currentPrice",
          tax: "$products.tax",
        },
      },
      {
        $group: {
          _id: null,
          total: { $sum: { $multiply: ["$quantity", "$currentPrice"] } },
          totalTax: { $sum: { $multiply: ["$quantity", "$tax"] } },
          totalWithTax: { $sum: { $multiply: ["$quantity", { $add: ["$currentPrice", "$tax"] }] } },
        },
      },
    ]);

    res.json({ total: totals });
  } catch (error) {
    console.error(error);
    res.status(500).json({ error: "Internal Server Error" });
  }
};
