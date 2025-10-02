import express from 'express';
import nodemailer from 'nodemailer';
import cors from 'cors';
import bodyParser from 'body-parser';
import 'dotenv/config';
import rateLimit from 'express-rate-limit';
import jwt from 'jsonwebtoken';
import { v4 as uuidv4 } from 'uuid';
import fetch from 'node-fetch';

const usedResetTokens = {};
const codes = {};

const app = express();
app.use(cors());
app.use(bodyParser.json());

function gerarResetToken(email) {
    const jti = uuidv4();
    const payload = {
        sub: email,
        purpose: 'password_reset'
    };
    const options = {
        expiresIn: '15m',
        jwtid: jti,
    };
    const token = jwt.sign(payload, process.env.RESET_SECRET, options);
    
    usedResetTokens[jti] = { 
        used: false, 
        expires: Date.now() + 15 * 60 * 1000 
    };
    
    return { token, jti, expiresIn: 15 * 60 };
}

async function salvarTokenNoBackend(email, token, jti) {
    try {
        const response = await fetch(
            `${process.env.VITE_API_URL}/usuarios/${encodeURIComponent(email)}/reset-token`, 
            {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json'
                },
                body: JSON.stringify({
                    resetToken: token,
                    jti: jti
                })
            }
        );

        if (!response.ok) {
            const error = await response.text();
            throw new Error(`Erro ao salvar token no backend: ${error}`);
        }

        if (response.status === 204) {
            return { success: true }; 
        }

        const contentType = response.headers.get('content-type');
        if (contentType && contentType.includes('application/json')) {
            return await response.json();
        }

        return { success: true }; 
    } catch (error) {
        console.error('Erro ao sincronizar token com backend:', error);
        throw error;
    }
}

const limiter = rateLimit({
    windowMs: 15 * 60 * 1000, 
    max: 20, 
    message: 'Muitas requisições, tente novamente mais tarde.'
});

app.post('/enviar-codigo', limiter, async (req, res) => {
    const { email } = req.body;
    
    if (!email) {
        return res.status(400).json({ 
            success: false, 
            message: 'E-mail é obrigatório.' 
        });
    }

    // Valida formato do email
    const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
    if (!emailRegex.test(email)) {
        return res.status(400).json({ 
            success: false, 
            message: 'E-mail inválido.' 
        });
    }

    // Verifica se usuário existe no backend Java
    try {
        const usuarioResponse = await fetch(
            `${process.env.VITE_API_URL}/usuarios/buscar-por-email/${encodeURIComponent(email)}`
        );
        
        if (!usuarioResponse.ok) {
            return res.status(404).json({ 
                success: false, 
                message: 'Usuário não encontrado.' 
            });
        }
    } catch (error) {
        console.error('Erro ao verificar usuário:', error);
        return res.status(500).json({ 
            success: false, 
            message: 'Erro ao verificar usuário no sistema.' 
        });
    }
   
    // Gera código de 6 dígitos
    const codigo = Math.floor(100000 + Math.random() * 900000).toString();
    
    // Salva o código (expira em 5 minutos)
    codes[email] = { 
        codigo, 
        expires: Date.now() + 5 * 60 * 1000 
    };

    // Configura transporter do Nodemailer
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
        res.json({ 
            success: true, 
            message: 'Código enviado!' 
        });
    } catch (error) {
        console.error('Erro ao enviar e-mail:', error);
        res.status(500).json({ 
            success: false, 
            message: 'Erro ao enviar e-mail.' 
        });
    }
});

// Endpoint para verificar código e gerar token
app.post('/verificar-codigo', async (req, res) => {
    const { email, codigo } = req.body;
    
    if (!email || !codigo) {
        return res.status(400).json({ 
            success: false, 
            message: 'Dados incompletos.' 
        });
    }

    const registro = codes[email];
    
    if (!registro) {
        return res.status(400).json({ 
            success: false, 
            message: 'Nenhum código pendente para este e-mail.' 
        });
    }

    if (registro.codigo !== codigo) {
        return res.status(400).json({ 
            success: false, 
            message: 'Código inválido.' 
        });
    }

    if (Date.now() >= registro.expires) {
        delete codes[email];
        return res.status(400).json({ 
            success: false, 
            message: 'Código expirado.' 
        });
    }

    // Código válido - gera o reset token
    const { token, jti } = gerarResetToken(email);
    
    try {
        // Salva o token no backend Java
        await salvarTokenNoBackend(email, token, jti);
        
        // Remove o código usado
        delete codes[email];
        
        res.json({ 
            success: true, 
            resetToken: token,
            message: 'Código verificado com sucesso!' 
        });
    } catch (error) {
        console.error('Erro ao sincronizar token:', error);
        res.status(500).json({ 
            success: false, 
            message: 'Erro ao processar verificação.' 
        });
    }
});

// Endpoint para validar se token já foi usado (opcional)
app.post('/validar-token', (req, res) => {
    const { jti } = req.body;
    
    if (!jti) {
        return res.status(400).json({ 
            valid: false, 
            message: 'JTI não fornecido.' 
        });
    }

    const tokenInfo = usedResetTokens[jti];
    
    if (!tokenInfo) {
        return res.json({ 
            valid: false, 
            message: 'Token não encontrado.' 
        });
    }

    if (tokenInfo.used) {
        return res.json({ 
            valid: false, 
            message: 'Token já foi utilizado.' 
        });
    }

    if (Date.now() >= tokenInfo.expires) {
        return res.json({ 
            valid: false, 
            message: 'Token expirado.' 
        });
    }

    res.json({ 
        valid: true, 
        message: 'Token válido.' 
    });
});

// Endpoint para marcar token como usado (chamado após sucesso)
app.post('/marcar-token-usado', (req, res) => {
    const { jti } = req.body;
    
    if (!jti) {
        return res.status(400).json({ 
            success: false, 
            message: 'JTI não fornecido.' 
        });
    }

    if (usedResetTokens[jti]) {
        usedResetTokens[jti].used = true;
    }

    res.json({ 
        success: true, 
        message: 'Token marcado como usado.' 
    });
});

// Limpeza periódica de tokens expirados
setInterval(() => {
    const now = Date.now();
    
    // Limpa códigos expirados
    for (const email in codes) {
        if (codes[email].expires < now) {
            delete codes[email];
        }
    }
    
    // Limpa tokens expirados
    for (const jti in usedResetTokens) {
        if (usedResetTokens[jti].expires < now) {
            delete usedResetTokens[jti];
        }
    }
}, 5 * 60 * 1000); // A cada 5 minutos

const PORT = process.env.PORT || 3001;
app.listen(PORT, () => {
    console.log(`Servidor rodando na porta ${PORT}`);
});