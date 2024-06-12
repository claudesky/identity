import nodemailer from 'nodemailer'

interface email {
  to: string
  subject: string
  text: string
}

export const sendEmail = async (email: email) => {
  try {
    const Transporter = nodemailer.createTransport({
      host: process.env.MAIL_HOST,
      port: Number(process.env.MAIL_PORT),
      auth: {
        user: process.env.MAIL_USERNAME,
        pass: process.env.MAIL_PASSWORD,
      },
    });
    return await Transporter.sendMail({
      from: process.env.MAIL_FROM,
      ...email
    })
  } catch (error) {
    console.log(error)
    throw error
  }
}
