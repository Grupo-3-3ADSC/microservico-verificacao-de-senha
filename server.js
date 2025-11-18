import express from 'express';
import nodemailer from 'nodemailer';
import cors from 'cors';
import bodyParser from 'body-parser';
import 'dotenv/config';
import rateLimit from 'express-rate-limit';
import jwt from 'jsonwebtoken';
import { v4 as uuidv4 } from 'uuid';
import fetch from 'node-fetch';
import { createClient } from 'redis';

const app = express();
app.use(cors());
app.use(bodyParser.json());

// Configurar Redis Client
const redisClient = createClient({
    url: process.env.REDIS_URL || 'redis://localhost:6379'
});

redisClient.on('error', (err) => console.error('Redis Client Error', err));
redisClient.on('connect', () => console.log('✅ Conectado ao Redis'));

await redisClient.connect();

// Prefixos para organizar as chaves no Redis
const REDIS_PREFIX = {
    CODE: 'reset:code:',           // reset:code:email@example.com
    TOKEN: 'reset:token:',         // reset:token:jti-uuid
};

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

    const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
    if (!emailRegex.test(email)) {
        return res.status(400).json({ 
            success: false, 
            message: 'E-mail inválido.' 
        });
    }

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
   
    const codigo = Math.floor(100000 + Math.random() * 900000).toString();
    
    // Salva o código no Redis com expiração de 5 minutos
    const codigoKey = `${REDIS_PREFIX.CODE}${email}`;
    await redisClient.setEx(codigoKey, 5 * 60, codigo);

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
        
        // Remove o código do Redis se o email falhar
        await redisClient.del(codigoKey);
        
        res.status(500).json({ 
            success: false, 
            message: 'Erro ao enviar e-mail.' 
        });
    }
});

app.post('/verificar-codigo', async (req, res) => {
    const { email, codigo } = req.body;
    
    if (!email || !codigo) {
        return res.status(400).json({ 
            success: false, 
            message: 'Dados incompletos.' 
        });
    }

    const codigoKey = `${REDIS_PREFIX.CODE}${email}`;
    const codigoArmazenado = await redisClient.get(codigoKey);
    
    if (!codigoArmazenado) {
        return res.status(400).json({ 
            success: false, 
            message: 'Nenhum código pendente ou código expirado.' 
        });
    }

    if (codigoArmazenado !== codigo) {
        return res.status(400).json({ 
            success: false, 
            message: 'Código inválido.' 
        });
    }

    // Código válido - gera o reset token
    const { token, jti } = gerarResetToken(email);
    
    try {
        // Salva informações do token no Redis (marca como não usado)
        const tokenKey = `${REDIS_PREFIX.TOKEN}${jti}`;
        const tokenData = JSON.stringify({
            email,
            used: false,
            createdAt: Date.now()
        });
        await redisClient.setEx(tokenKey, 15 * 60, tokenData); // 15 minutos
        
        // Salva o token no backend Java
        await salvarTokenNoBackend(email, token, jti);
        
        // Remove o código usado
        await redisClient.del(codigoKey);
        
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

app.post('/validar-token', async (req, res) => {
    const { jti } = req.body;
    
    if (!jti) {
        return res.status(400).json({ 
            valid: false, 
            message: 'JTI não fornecido.' 
        });
    }

    const tokenKey = `${REDIS_PREFIX.TOKEN}${jti}`;
    const tokenData = await redisClient.get(tokenKey);
    
    if (!tokenData) {
        return res.json({ 
            valid: false, 
            message: 'Token não encontrado ou expirado.' 
        });
    }

    try {
        const parsed = JSON.parse(tokenData);
        
        if (parsed.used) {
            return res.json({ 
                valid: false, 
                message: 'Token já foi utilizado.' 
            });
        }

        res.json({ 
            valid: true, 
            message: 'Token válido.',
            email: parsed.email
        });
    } catch (error) {
        console.error('Erro ao parsear token data:', error);
        res.status(500).json({ 
            valid: false, 
            message: 'Erro ao validar token.' 
        });
    }
});

app.post('/marcar-token-usado', async (req, res) => {
    const { jti } = req.body;
    
    if (!jti) {
        return res.status(400).json({ 
            success: false, 
            message: 'JTI não fornecido.' 
        });
    }

    const tokenKey = `${REDIS_PREFIX.TOKEN}${jti}`;
    const tokenData = await redisClient.get(tokenKey);
    
    if (!tokenData) {
        return res.status(404).json({ 
            success: false, 
            message: 'Token não encontrado.' 
        });
    }

    try {
        const parsed = JSON.parse(tokenData);
        parsed.used = true;
        parsed.usedAt = Date.now();
        
        // Mantém o token marcado como usado até expirar naturalmente
        const ttl = await redisClient.ttl(tokenKey);
        if (ttl > 0) {
            await redisClient.setEx(tokenKey, ttl, JSON.stringify(parsed));
        }

        res.json({ 
            success: true, 
            message: 'Token marcado como usado.' 
        });
    } catch (error) {
        console.error('Erro ao marcar token:', error);
        res.status(500).json({ 
            success: false, 
            message: 'Erro ao processar.' 
        });
    }
});

// Health check
app.get('/health', async (req, res) => {
    try {
        await redisClient.ping();
        res.json({ status: 'ok', redis: 'connected' });
    } catch (error) {
        res.status(503).json({ status: 'error', redis: 'disconnected' });
    }
});

const PORT = process.env.PORT || 3001;
app.listen(PORT, () => {
    console.log(`🚀 Servidor rodando na porta ${PORT}`);
});