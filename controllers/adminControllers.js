const Admin = require("../models/adminSchema");
const Category = require("../models/categorySchema");
const Order = require("../models/orderSchema");
const User = require("../models/userSchema")
const Wallet = require('../models/walletSchema')
const multer = require("multer");
const bcrypt = require("bcrypt");
const mongoose = require('mongoose')
const { startOfMonth, endOfMonth, getMonth, format } = require('date-fns');

exports.getDashboard = async (req, res, next) => {
  let adminDetails = req.session.admin;
  const orders = await Order.find({})
    .populate({
      path: "products.item",
      model: "Product",
    })
    .exec();

  const totalQuantity = orders.reduce((accumulator, order) => {
    order.products.forEach((product) => {
      accumulator += product.quantity;
    });
    return accumulator;
  }, 0);

  const totalProfit = orders.reduce((acc, order) => {
    return acc + order.totalAmount;
  }, 0);

  const totalShipped = orders.reduce((accumulator, order) => {
    order.products.forEach((product) => {
      if (product.deliverystatus === "shipped") {
        accumulator += 1;
      }
    });
    return accumulator;
  }, 0);
  const totalCancelled = orders.reduce((accumulator, order) => {
    order.products.forEach((product) => {
      if (product.orderstatus === "cancelled") {
        accumulator += 1;
      }
    });
    return accumulator;
  }, 0);

 
  //console.log(orders.products,"zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz");


 

  const categoryCounts = await (async () => {
    try {
      // Retrieve all orders
      console.log(orders, "order details");
  
      // Object to store category names and their respective count
      const categoryCount = {};
  
      // Iterate over the orders
      for (const order of orders) {
        // Iterate over the products within each order
        for (const product of order.products) {
          // Retrieve the category from the "item" field
          const categoryId = product.item.category;
  
          // Populate the category field with actual category data
          const category = await Category.findById(categoryId).exec();
  
          // Increment the category count
          if (category) {
            const categoryName = category.category;
  
            if (categoryCount[categoryName]) {
              categoryCount[categoryName].count++;
            } else {
              categoryCount[categoryName] = {
                name: categoryName,
                count: 1,
              };
            }
          }
        }
      }
  
      // Object to store category names and their respective count
      const categoryCounts = {};
  
      // Output the category names and counts
      for (const categoryName in categoryCount) {
        const categoryData = categoryCount[categoryName];
        console.log(`Category: ${categoryData.name}, Count: ${categoryData.count}`);
        categoryCounts[categoryData.name] = categoryData.count;
      }
  
      console.log(categoryCounts);
  
      // Return the categoryCounts object
      return categoryCounts;
    } catch (error) {
      console.error(error);
    }
  })();
  
  
  
     console.log(categoryCounts,"cxcxccxcxccxccxcxc");




  function countPaymentMethods(orders) {
    let paymentCounts = {
      RazorPay: 0,
      COD: 0,
      Wallet: 0,
    };

    for (let order of orders) {
      const paymentMethod = order.paymentMethod;

      switch (paymentMethod) {
        case "RazorPay":
          paymentCounts.RazorPay++;
          break;
        case "COD":
          paymentCounts.COD++;
          break;
        case "Wallet":
          paymentCounts.Wallet++;
          break;
      }
    }

    return paymentCounts;
  }

  function calculatePaymentMethodPercentage(orders) {
    let paymentCounts = countPaymentMethods(orders);
    let totalOrders = orders.length;

    let paymentPercentages = {};

    for (let paymentMethod in paymentCounts) {
      let count = paymentCounts[paymentMethod];
      let percentage = (count / totalOrders) * 100;
      paymentPercentages[paymentMethod] = percentage.toFixed(2) + "%";
    }

    return paymentPercentages;
  }

  const paymentPercentages = calculatePaymentMethodPercentage(orders);
  console.log(paymentPercentages);

  //console.log(totPayment,"xxxxxxxxxxxx");

  const startOfYear = new Date(new Date().getFullYear(), 0, 1); // start of the year
  const endOfYear = new Date(new Date().getFullYear(), 11, 31); // end of the year

  let orderBasedOnMonths = await Order.aggregate([
    // match orders within the current year
    { $match: { createdAt: { $gte: startOfYear, $lte: endOfYear } } },

    // group orders by month
    {
      $group: {
        _id: { $month: "$createdAt" },
        orders: { $push: "$$ROOT" },
      },
    },

    // project the month and orders fields
    {
      $project: {
        _id: 0,
        month: "$_id",
        orders: 1,
      },
    },
    {
      $project: {
        month: 1,
        orderCount: { $size: "$orders" },
      },
    },
    {
      $sort: { month: 1 },
    },
  ]);

  // console.log(orderBasedOnMonths, "vall");
  order_count = orderBasedOnMonths[0]["orderCount"];
  // console.log(order_count);
  //  console.log(totalQuantity,totalProfit,totalShipped,totalCancelled,'ordercount')
  res.render("admin/adminHome", {
    admin: true,
    adminDetails,
    totalQuantity,
    order_count,
    totalProfit,
    totalShipped,
    totalCancelled,
    orderBasedOnMonths,
    noShow: true,
    paymentPercentages,
    categoryCounts,
  });
};


exports.adminLogin = async (req, res) => {
  if (req.session.admin) {
    res.redirect("/admin/home");
  } else {
    const adminErr = req.session.adminErr;
    req.session.adminErr = false;
    res.render("admin/adminLogin", { other: true, login: adminErr });
  }
};

exports.postAdminLogin = async (req, res) => {
  try {
    const { email, password } = req.body;
    const admin = await Admin.findOne({ email });

    if (!admin) {
      // No admin user found with this email address
      console.log("Invalid email or password");
      req.session.adminErr = "Invalid email or password";
      return res.redirect("/admin/login");
    }

    const isPasswordValid = await bcrypt.compare(password, admin.password);
    if (!isPasswordValid) {
      // Password is incorrect
      console.log("Invalid email or password");
      req.session.adminErr = "Invalid email or password";
      return res.redirect("/admin/login");
    }

    // Authentication successful - create session
    req.session.admin = admin;
    req.session.adminloggedIn = true;
    res.redirect("/admin/home");

  } catch (error) {
    console.log(error);
    req.session.adminErr = "Something went wrong";
    res.redirect("/admin/login");
  }
};

exports.logout = async (req, res) => {
  req.session.admin = null;
  req.session.destroy();
  res.redirect("/admin/login");
};

exports.addCategory = async (req, res) => {
  if (req.session.admin) {
    const category_data = await Category.find();
    res.render("admin/addCategory", { other: false, category: category_data, admin: true });
  } else {
    res.redirect("admin/login");
  }
};

exports.addCategoryPost = async (req, res) => {
  try {
    const category_data = await Category.find();
    if (category_data.length > 0) {
      let checking = false;
      for (let i = 0; i < category_data.length; i++) {
        if (category_data[i]["category"].toLowerCase() === req.body.category.toLowerCase()) {
          checking = true;
          break;
        }
      }
      if (checking == false) {
        let category = new Category({
          category: req.body.category,
          // description: req.body.description,
        });

        const cart_data = await category.save();
        res.redirect("/admin/products");
        console.log("new category added");
        // res.send('Category added successfully');
      } else {
        res.redirect("/admin/add-category");
        console.log("category already exists");
        // res.status(200).send({success:true, msg: "This category ("+req.body.category+")is already exists."})
      }
    } else {
      const category = new Category({
        category: req.body.category,
        // description: req.body.description,
      });
      await category.save();
      console.log("newcategory");
    }
  } catch (error) {
    console.error(error);
    res.status(500).send("Internal Server Error");
  }
};

exports.viewOrders = async (req, res) => {
  let userId = req.session.user;
  const perPage = 4;
  try {
    let orders = await Order.find()
      .populate({
        path: 'userId',
        model: 'User',
        select: 'name email' // select the fields you want to include from the User document
      })
      .populate({
        path: 'products.item',
        model: 'Product'
      })
      .exec();

    let count = 0
    orders.forEach(order => {
      count += order.products.length
    })


    res.locals.orders = orders;


    res.render('admin/viewOrders', { admin: true, pages: Math.ceil(count / perPage) });
  } catch (error) {
    console.log(error);
  }
};
// load data
exports.loadOrderData = async (req, res) => {
  const perPage = 5
  const page = req.query.page
  const orders = await Order.find({}).skip((page - 1) * perPage).limit(perPage).populate({
    path: 'userId',
    model: 'User'
  })
  res.json(orders)
}

exports.userslist = async (req, res) => {
  try {
    let adminDetails = req.session.admin;
    const userList = await User.find({});
    res.render("admin/usersList", { userList, admin: true, adminDetails });
  } catch (error) {
    console.log(error);
  }
}

exports.orderedProducts = async (req, res) => {
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

    const orderedProductDetails = order.products.map((product) => {
      return {
        product: product.item,
        quantity: product.quantity,
      };
    });

    res.render("admin/orderedProducts", {
      admin: true,
      user: req.session.user,
      order,
      orderedProductDetails,
    });
  } catch (error) {
    console.error(error);
    res.status(500).send("Internal Server Error");
  }
};

exports.orderStatus = async (req, res) => {

  let productId = req.query.productId
  let orderId = req.query.orderId;
  const deliveryStatus = req.body.deliveryStatus;

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
      if (deliveryStatus == 'cancelled') {
        product.orderstatus = deliveryStatus;
        product.deliverystatus = deliveryStatus;
      } else {
        product.orderstatus = 'confirmed';
        product.deliverystatus = deliveryStatus;
      }

      await order.save();
      break; // Exit the loop once product is found
    }
  }
  res.redirect('/admin/orders')
}

exports.salesSummary = async (req, res) => {
  let adminDetails = req.session.admin;
  let orders = await Order.find()
  const latestHitsData = await getLatestHitsData()
    .populate({
      path: 'userId',
      model: 'User',
      select: 'name email' // select the fields you want to include from the User document
    })
    .populate({
      path: 'products.item',
      model: 'Product'
    })
    .exec();

  if (req.session.admin.orderThisWeek) {
    res.locals.orders = req.session.admin.orderThisWeek;
    req.session.admin.orderThisWeek = null;
  } else if (req.session.admin.orderThisMonth) {
    res.locals.orders = req.session.admin.orderThisMonth;
    req.session.admin.orderThisMonth = null;
  } else if (req.session.admin.orderThisDay) {
    res.locals.orders = req.session.admin.orderThisDay;
    req.session.admin.orderThisDay = null;
  } else if (req.session.admin.orderThisYear) {
    res.locals.orders = req.session.admin.orderThisYear;
    req.session.admin.orderThisYear = null;
  } else {
    res.locals.orders = orders;
  }
  res.render('admin/adminHome', { admin: true, adminDetails, latestHitsData })
}


exports.salesReport = async (req, res) => {
  console.log(req.body.selector, 'report body ');
  const selector = req.body.selector;

  // Extracting the relevant parts based on the selector
  let year, month, weekStart, weekEnd, day;
  if (selector.startsWith('year')) {
    year = parseInt(selector.slice(5));
  } else if (selector.startsWith('month')) {
    const parts = selector.split('-');
    year = parseInt(parts[1]);
    month = parseInt(parts[2]);
  } else if (selector.startsWith('week')) {
    const today = new Date();
    weekStart = new Date(today.getFullYear(), today.getMonth(), today.getDate() - today.getDay());
    weekEnd = new Date(today.getFullYear(), today.getMonth(), today.getDate() - today.getDay() + 6);
    console.log(weekStart, 'weekstart');
    console.log(weekEnd, 'weekEnd');
  } else if (selector.startsWith('day')) {
    day = new Date(selector.slice(4));
    day.setHours(0, 0, 0, 0);
  }

  if (weekStart && weekEnd) {
    const orderThisWeek = await Order.find({ createdAt: { $gte: weekStart, $lte: weekEnd } })
      .populate({
        path: 'userId',
        model: 'User',
        select: 'name email' // select the fields you want to include from the User document
      })
      .populate({
        path: 'products.item',
        model: 'Product'
      })
      .exec();
    req.session.admin.orderThisWeek = orderThisWeek;
    console.log(orderThisWeek, 'details of this week');
    res.locals.orders = orderThisWeek; // Update the orders data for rendering
  } else if (year && month) {
    const startOfMonth = new Date(year, month - 1, 1);
    const endOfMonth = new Date(year, month, 0, 23, 59, 59, 999);
    const orderThisMonth = await Order.find({ createdAt: { $gte: startOfMonth, $lte: endOfMonth } })
      .populate({
        path: 'userId',
        model: 'User',
        select: 'name email' // select the fields you want to include from the User document
      })
      .populate({
        path: 'products.item',
        model: 'Product'
      })
      .exec();
    req.session.admin.orderThisMonth = orderThisMonth;
    console.log(orderThisMonth, 'details of this month');
    res.locals.orders = orderThisMonth; // Update the orders data for rendering
  } else if (day) {
    const startOfDay = new Date(day);
    const endOfDay = new Date(day);
    endOfDay.setDate(endOfDay.getDate() + 1);
    endOfDay.setSeconds(endOfDay.getSeconds() - 1);
    const orderThisDay = await Order.find({ createdAt: { $gte: startOfDay, $lte: endOfDay } })
      .populate({
        path: 'userId',
        model: 'User',
        select: 'name email' // select the fields you want to include from the User document
      })
      .populate({
        path: 'products.item',
        model: 'Product'
      })
      .exec();
    req.session.admin.orderThisDay = orderThisDay;
    console.log(orderThisDay, 'details of this day');
    res.locals.orders = orderThisDay; // Update the orders data for rendering
  } else if (year) {
    const orderThisYear = await Order.find({
      createdAt: { $gte: new Date(year, 0, 1), $lte: new Date(year, 11, 31, 23, 59, 59, 999) }
    })
      .populate({
        path: 'userId',
        model: 'User',
        select: 'name email' // select the fields you want to include from the User document
      })
      .populate({
        path: 'products.item',
        model: 'Product'
      })
      .exec();
    req.session.admin.orderThisYear = orderThisYear;
    console.log(orderThisYear, 'details of this year');
    res.locals.orders = orderThisYear; // Update the orders data for rendering
  }

  let adminDetails = req.session.admin;
  res.render('admin/adminHome', { admin: true, adminDetails });
};
