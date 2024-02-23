const express = require("express");
const app = express();
const mongoose = require("mongoose");
const dotenv = require("dotenv");
const adminUser = require("./routes/adminUser");
const cors = require("cors");

dotenv.config();

mongoose
  .connect(process.env.MONGO_URL)
  .then(() => console.log("DB Connection Successful!"))
  .catch((err) => {
    console.log(err);
  });

app.use(cors());
app.use(express.json());
app.use("/api/auth", adminUser);

app.listen(process.env.PORT || 5000, () => {
  console.log("Backend server is running!");
});