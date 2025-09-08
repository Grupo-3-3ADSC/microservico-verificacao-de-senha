import express from 'express';
import nodemailer from 'nodemailer';
import cors from 'cors';
import bodyParser from 'body-parser';
import 'dotenv/config';

const app = express();
app.use(cors());
app.use(bodyParser.json());

// Armazene os códigos temporariamente (em produção, use um banco de dados ou cache)
const codes = {};

app.post('/enviar-codigo', async (req, res) => {
    const { email } = req.body;
    if (!email) return res.status(400).json({ success: false, message: 'E-mail é obrigatório.' });

    // Gera código de 6 dígitos
    const codigo = Math.floor(100000 + Math.random() * 900000).toString();

    // Salva o código associado ao e-mail (expira em 5 minutos)
    codes[email] = { codigo, expires: Date.now() + 5 * 60 * 1000 };

    // Configure o transporter do Nodemailer (exemplo com Gmail)
    const transporter = nodemailer.createTransport({
        service: 'gmail',
        auth: {
            user: 'cogniflow51@gmail.com',
            pass: process.env.GMAIL_PASS
        }
    });

    const mailOptions = {
        from: '"CogniFlow" <cogniflow51@gmail.com>',
        to: email,
        subject: 'Código de Verificação - Mega Plate',
        text: `Seu código de verificação é: ${codigo}`,
        html: `<p>Seu código de verificação é: <b>${codigo}</b></p>`
    };

    try {
        await transporter.sendMail(mailOptions);
        res.json({ success: true, message: 'Código enviado!' });
    } catch (error) {
        res.status(500).json({ success: false, message: 'Erro ao enviar e-mail.' });
    }
});

// Endpoint para verificar o código
app.post('/verificar-codigo', (req, res) => {
    const { email, codigo } = req.body;
    if (!email || !codigo) return res.status(400).json({ success: false, message: 'Dados incompletos.' });

    const registro = codes[email];
    if (registro && registro.codigo === codigo && Date.now() < registro.expires) {
        delete codes[email]; // Código só pode ser usado uma vez
        res.json({ success: true });
    } else {
        res.status(400).json({ success: false, message: 'Código inválido ou expirado.' });
    }
});

app.listen(3001, () => {
    console.log('Servidor rodando na porta 3001');
});