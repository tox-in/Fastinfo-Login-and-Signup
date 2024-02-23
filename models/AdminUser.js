const mongoose = require("mongoose");

const AdminUserSchema = new mongoose.Schema(
    {
        email: {type: String, required: true, unique: true},
        password: {type: String, required: true},
        username: { type: String, required: true},
        isAdmin: {
            type:Boolean,
            default: false
        }
    },
    {timestamps: true}
);

module.exports = mongoose.model("Admin", AdminUserSchema);