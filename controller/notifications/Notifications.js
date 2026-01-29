import sgMail from '@sendgrid/mail';
import OrderConfirmationTemplate from "./templates/OrderConfirmationTemplate.js";

const defaults = {
    from: {
        name: 'GreenGo',
        email: 'usamamukhtar.work@gmail.com',
    }
}

export const orderConfirmation = async (req, res) => {
    const {to, order} = req.body;
    const email = {
        ...defaults,
        to,
        subject: "Order Confirmation",
        text: `Your order #${order.order_id} has been placed successfully. ${order.products.length} items will be sent to ${order.address} by ${order.ordered_at}. Your grand total is ${order.total}`,
        html: OrderConfirmationTemplate(order)
    }

    await sendEmail(email, res);
}

const sendEmail = async (email, res) => {
    try {
        await sgMail.send(email);
        console.log(`Email sent to ${email.to}`);
        res.status(200).json({email, result: 'Sent Successfully'});
    } catch (e) {
        console.error("Error in sending email");
        res.status(400).json({message: e.message});
    }
}