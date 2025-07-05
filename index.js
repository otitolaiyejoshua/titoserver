const express = require('express');
const mysql = require('mysql2');
const multer = require('multer');
const path = require('path');
const storage = multer.diskStorage({
  destination:'uploads/',
  filename: (req,file,cb)=>{
    cb(null,Date.now()+path.extname(file.originalname));
  },
});
const upload = multer({storage});

const cookieParser = require('cookie-parser')
const bodyParser = require('body-parser');
const cors = require('cors');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const app = express();
const SECRET_KEY = process.env.JWT_SECRET;
const PORT = process.env.PORT || 5000;
app.use(bodyParser.urlencoded({ extended: true }));
app.use(bodyParser.json());
app.use(cors({
    origin:'https://titoclient.vercel.app'
}));

const db = mysql.createConnection({
  host: process.env.DB_HOST,
  user: process.env.DB_USER,
  port: process.env.DB_PORT,
  password: process.env.DB_PASS,
  database: process.env.DB_NAME,
});

db.connect((err)=>{
    if(err) throw err;
    console.log('connected to Database')
});
const requireAuth = (req, res, next) => {
  const token = req.headers.authorization?.split(" ")[1]; // Extract token from Bearer token

  if (!token) {
      return res.status(401).json({ message: "Unauthorized: No token provided" });
  }

  jwt.verify(token, SECRET_KEY, (err, decoded) => {
      if (err) {
          return res.status(401).json({ message: "Unauthorized: Invalid token" });
      }
      req.user = decoded; // Store user info in request object
      next();
  });
};
app.post('/api/register', (req, res) => {
    const { username, email, password } = req.body;
  
    // Validate the data (e.g., check if required fields are provided)
    if (!username || !email || !password) {
      return res.status(400).json({ message: 'Please provide all required fields' });
    }
  
    // Check if the email is already registered (optional, depending on your requirements)
    db.query('SELECT * FROM users WHERE email = ?', [email], (err, results) => {
      if (err) {
        console.error('Error checking user existence:', err);
        return res.status(500).json({ message: 'Internal server error' });
      }
      if (results.length > 0) {
        return res.json({ message: 'Email is already registered' });
      }
  
      // Hash the password before saving it to the database
      bcrypt.hash(password, 10, (err, hash) => {
        if (err) {
          console.error('Error hashing password:', err);
          return res.status(500).json({ message: 'Internal server error' });
        }
  
        // Save the user data to the database
        const newUser = { username, email, password: hash };
        db.query('INSERT INTO users SET ?', newUser, (err, result) => {
          if (err) {
            console.error('Error saving user to database:', err);
            return res.status(500).json({ message: 'Internal server error' });
          }
          console.log('User registered:', result);
          res.status(200).json({ message: 'User registered successfully' });
        });
    });
});
});
app.post('/api/login', async (req, res) => {
    const { username, password } = req.body;
    const selectUserQuery = 'SELECT * FROM users WHERE username = ?';
    db.query(selectUserQuery, [username], async (err, results) => {
      if (err) {
        console.error('Error fetching user:', err);
        res.json({ message: 'Invalid credentials' });
      }if (results.length === 0) {
        res.json({ message: 'Invalid credentials' });
      }
      else{
        const users = results[0];
        bcrypt.compare(password,users.password,(err,result)=>{
          if(err||!result){
            return res.json({message:'Invalid credentials'});
          }
          const token = jwt.sign({userId: users.id},SECRET_KEY,{expiresIn:'1h'});
          res.json({token});
        })
      }
    });
    });
    app.post('/api/tweets',upload.single('image'), (req, res) => {
      const { caption} = req.body;// This is set by the authentication middleware
      const userId = req.body.userId;
      console.log(userId)
      const insertTweetQuery = 'INSERT INTO tweets ( userId,caption,imageUrl) VALUES (?, ?,?)';
      if(req.file && caption){
      const imageUrl = req.file.filename;
       const query = db.query(insertTweetQuery, [userId,caption,imageUrl], (err, result) => {
        if (err) {
          console.error('Error posting tweet:', err);
          res.status(500).json({ message: 'Error posting tweet' });
        } else {
          res.json({ message: 'Tweet posted successfully' });
        }
      });
      console.log(query);
    }if(!req.file){
      db.query(insertTweetQuery,[userId,caption,null],(error,result)=>{
        if(error){
          console.error('Error uploading',error)
          return res.status(500).json({message:'Error uploading'});
        }
        res.status(201).json({message:'Tweet posted successfully'})
      })
    }
    if(!caption){
      const imageUrl = req.file.filename;
      db.query(insertTweetQuery,[userId,'',imageUrl],(error,result)=>{
        if(error){
          console.error('Error uploading',error)
          return res.status(500).json({message:'Error uploading'});
        }
        res.status(201).json({message:'Tweet posted successfully'})
      })
    }
    });
    app.use('/uploads',express.static(path.join(__dirname,'uploads')));
    app.get('/api/tweets', (req, res) => {
      const getTweetsQuery = 'SELECT t.id,t.caption,t.imageUrl,t.userId,u.username,u.profile_picture FROM tweets t JOIN users u ON t.userId =u.id ';
      db.query(getTweetsQuery, (err, results) => {
        if (err) {
          console.error('Error fetching tweets:', err);
          res.status(500).json({ message: 'Error fetching tweets' });
        } else {
          res.json(results);
        }
      });
    });
app.get('/api/user/:id', (req, res) => {
  const id = req.params.id;

  const userQuery = `
    SELECT 
      users.id, users.bio, users.username, users.profile_picture,
      (SELECT COUNT(*) FROM followers WHERE followed_id = users.id) AS followers_count
    FROM users
    WHERE users.id = ?
  `;

  const postsQuery = `
    SELECT tweets.id as tweet_id, tweets.caption, tweets.imageUrl,
      (SELECT COUNT(*) FROM likes WHERE tweet_id = tweets.id) AS like_count
    FROM tweets
    WHERE tweets.userid = ?
  `;

  db.query(userQuery, [id], (err, userResults) => {
    if (err) {
      console.log(err);
      return res.status(500).json({ message: "Server error" });
    }
    if (userResults.length === 0) {
      return res.status(404).json({ message: "User not found" });
    }

    const user = userResults[0];

    db.query(postsQuery, [id], (err, postResults) => {
      if (err) {
        console.log(err);
        return res.status(500).json({ message: "Server error" });
      }

      const totalLikes = postResults.reduce((sum, post) => sum + post.like_count, 0);

      const posts = postResults.map(p => ({
        id: p.tweet_id,
        caption: p.caption,
        imageUrl: p.imageUrl,
        like_count: p.like_count
      }));

      const userData = {
        id: user.id,
        username: user.username,
        bio: user.bio,
        profile_picture: user.profile_picture,
        followers: user.followers_count,
        totalLikes: totalLikes,
        posts
      };

      return res.status(200).json(userData);
    });
  });
});

app.get('/api/users/:username', (req, res) => {
  const username = req.params.username;

  const userInfoQuery = `
    SELECT 
      u.id AS userId,
      u.username,
      u.bio,
      u.profile_picture,
      (SELECT COUNT(*) FROM followers WHERE followed_id = u.id) AS followers_count,
      (SELECT COUNT(*) FROM tweets WHERE userid = u.id) AS total_posts,
      (SELECT COUNT(*) FROM likes l JOIN tweets t ON l.tweet_id = t.id WHERE t.userid = u.id) AS total_likes
    FROM users u
    WHERE u.username = ?
    LIMIT 1
  `;

  const userPostsQuery = `
    SELECT 
      t.id,
      t.caption,
      t.imageUrl,
      u.username,
      u.profile_picture
    FROM tweets t
    INNER JOIN users u ON t.userid = u.id
    WHERE u.username = ?
    ORDER BY t.id DESC
  `;

  db.query(userInfoQuery, [username], (err, userResult) => {
    if (err) {
      console.error('User info query error:', err);
      return res.status(500).json({ error: 'Internal server error' });
    }

    if (userResult.length === 0) {
      return res.status(404).json({ message: 'User not found' });
    }

    const userData = userResult[0];

    db.query(userPostsQuery, [username], (err, postsResult) => {
      if (err) {
        console.error('Posts query error:', err);
        return res.status(500).json({ error: 'Internal server error' });
      }

      res.status(200).json({
        user: userData,
        posts: postsResult
      });
    });
  });
});

app.get('/api/users', requireAuth, (req, res) => {
  db.query('SELECT id, username, profile_picture FROM users', (err, rows) => {
    if (err) return res.status(500).json({ message: 'DB error' });
    res.json(rows);
  });
});
// Check if followerId is already following followedId
app.get('/api/follow/status', (req, res) => {
  const { followerId, followedId } = req.query;
  const query = 'SELECT * FROM followers WHERE follower_id = ? AND followed_id = ?';
  db.query(query, [followerId, followedId], (err, result) => {
    if (err) return res.status(500).json({ message: 'Error checking follow status' });
    res.json({ following: result.length > 0 });
  });
});

// 📌 FOLLOW / UNFOLLOW user
app.post('/api/users/:targetUserId/follow', requireAuth, (req, res) => {
  const followerId = req.user.userId; // From token
  const followedId = parseInt(req.params.targetUserId);

  if (followerId === followedId) {
    return res.status(400).json({ message: "You can't follow yourself" });
  }

  const checkQuery = 'SELECT id FROM followers WHERE follower_id = ? AND followed_id = ?';
  db.query(checkQuery, [followerId, followedId], (err, results) => {
    if (err) return res.status(500).json({ message: 'Database error' });

    if (results.length > 0) {
      // Already following → UNFOLLOW
      db.query('DELETE FROM followers WHERE follower_id = ? AND followed_id = ?', [followerId, followedId], (err) => {
        if (err) return res.status(500).json({ message: 'Error unfollowing user' });
        res.json({ following: false, message: 'User unfollowed' });
      });
    } else {
      // Not following → FOLLOW
      db.query('INSERT INTO followers (follower_id, followed_id) VALUES (?, ?)', [followerId, followedId], (err) => {
        if (err) return res.status(500).json({ message: 'Error following user' });
        res.json({ following: true, message: 'User followed' });
      });
    }
  });
});
// Route to check if the logged-in user is following another user
app.get('/api/follow/status/:userId/:targetUserId', (req, res) => {
  const { userId, targetUserId } = req.params;

  const q = 'SELECT * FROM followers WHERE follower_id = ? AND followed_id = ?';
  db.query(q, [userId, targetUserId], (err, results) => {
    if (err) {
      return res.status(500).json({ error: 'Database error' });
    }

    if (results.length > 0) {
      res.json({ following: true });
    } else {
      res.json({ following: false });
    }
  });
});

app.get('/api/tops/:userId/',(req,res)=>{
  const userId= (req.params.userId);
  const queries = 'SELECT * FROM likes WHERE user_id=?'
  db.query(queries,[userId],(err,result)=>{
    if(err) throw err
    if(result.length > 0){
      res.json(result)
    }
    if(result.length === 0){
      res.json({color:'black'})
    }
  })
})
app.post('/api/profilepic',upload.single('images'),(req,res)=>{
  const userId = req.body.userId;
  const bio = req.body.bio;
  const profile = req.file.filename;
  console.log(req.file)
  const queries = 'UPDATE users SET profile_picture = ?,bio=? WHERE id =?';
  if(profile){
    db.query(queries,[profile,bio,userId],(err,result)=>{
      if(err) throw err
      console.log(result)
      res.status(200).json({message:'Profile picture Uploaded successful'})
  })
}
  else{
    console.log("no file uploaded")
  } 

})
app.post('/api/tweets/:tweetid/like', (req, res) => {
  const { userId } = req.body;
  const tweetid = parseInt(req.params.tweetid, 10);

  if (!userId || isNaN(tweetid)) {
      return res.status(400).json({ message: 'Invalid User ID or Tweet ID' });
  }

  const checkQuery = 'SELECT id FROM likes WHERE user_id = ? AND tweet_id = ?';
  db.query(checkQuery, [userId, tweetid], (err, result) => {
      if (err) {
          console.error('Database error:', err);
          return res.status(500).json({ message: 'Database error' });
      }

      if (result.length > 0) {
          // Unlike the tweet
          const deleteQuery = 'DELETE FROM likes WHERE user_id = ? AND tweet_id = ?';
          db.query(deleteQuery, [userId, tweetid], (err) => {
              if (err) {
                  console.error('Database error:', err);
                  return res.status(500).json({ message: 'Database error' });
              }
              return res.json({ liked: false, message: 'Tweet unliked' });
          });
      } else {
          // Like the tweet
          const insertQuery = 'INSERT INTO likes (user_id, tweet_id) VALUES (?, ?)';
          db.query(insertQuery, [userId, tweetid], (err) => {
              if (err) {
                  console.error('Database error:', err);
                  return res.status(500).json({ message: 'Database error' });
              }
              return res.json({ liked: true, message: 'Tweet liked' });
          });
      }
  });
});

app.get('/api/tweets/:tweetid/likes', (req, res) => {
  const tweetid = parseInt(req.params.tweetid, 10);

  if (isNaN(tweetid)) {
      return res.status(400).json({ message: 'Invalid Tweet ID' });
  }

  const likesQuery = 'SELECT COUNT(id) AS likecounts FROM likes WHERE tweet_id = ?';
  db.query(likesQuery, [tweetid], (err, result) => {
      if (err) {
          console.error('Error fetching likes:', err);
          return res.status(500).json({ message: 'Database error' });
      }
      res.json({ likecounts: result[0].likecounts });
  });
});

// 📌 API: Get Tweet Details + Comments
app.get("/api/tweets/:tweetid/details", (req, res) => {
  const tweetId = req.params.tweetid;

  const tweetQuery = `SELECT tweets.*, users.username, users.profile_picture 
                      FROM tweets 
                      JOIN users ON tweets.userId = users.id 
                      WHERE tweets.id = ?`;

  const commentsQuery = `SELECT comments.*, users.username, users.profile_picture 
                         FROM comments 
                         JOIN users ON comments.user_id = users.id 
                         WHERE comments.tweet_id = ? 
                         ORDER BY comments.created_at DESC`;

  db.query(tweetQuery, [tweetId], (err, tweetResults) => {
      if (err) {
          console.error("Error fetching tweet:", err);
          return res.status(500).json({ error: "Internal Server Error" });
      }

      if (tweetResults.length === 0) {
          return res.status(404).json({ error: "Tweet not found" });
      }

      db.query(commentsQuery, [tweetId], (err, commentResults) => {
          if (err) {
              console.error("Error fetching comments:", err);
              return res.status(500).json({ error: "Internal Server Error" });
          }

          res.json({
              tweet: tweetResults[0],
              comments: commentResults
          });
      });
  });
});
app.post("/api/tweets/:tweetid/comments", requireAuth, (req, res) => {
  const { tweetid } = req.params;
  const { commentText } = req.body;
  const userId = req.user.userId; // Extracted from token

  if (!commentText.trim()) {
    return res.status(400).json({ message: "Comment cannot be empty" });
  }

  const query = "INSERT INTO comments (tweet_id, user_id, comment_text) VALUES (?, ?, ?)";
  db.query(query, [tweetid, userId, commentText], (err, result) => {
    if (err) {
      console.error("Error inserting comment:", err);
      return res.status(500).json({ message: "Database error" });
    }

    // Insert notification for the tweet owner
    const notificationMessage = `${req.user.username} commented on your post: ${commentText}`;
    const insertNotificationQuery = 'INSERT INTO notifications (user_id, notification_type, related_post_id, message) VALUES (?, "comment", ?, ?)';
    db.query(insertNotificationQuery, [req.user.userId, tweetid, notificationMessage], (err) => {
      if (err) {
        console.error('Error inserting notification:', err);
        return res.status(500).json({ message: 'Error inserting notification' });
      }
      res.status(201).json({
        message: "Comment posted successfully",
        commentId: result.insertId,
        tweetId: tweetid,
      });
    });
  });
});

// 📌 API: Post a New Comment (Protected)
app.post('/api/tweets/:tweetid/like', (req, res) => {
  const { userId } = req.body;
  const tweetid = parseInt(req.params.tweetid, 10);

  if (!userId || isNaN(tweetid)) {
    return res.status(400).json({ message: 'Invalid User ID or Tweet ID' });
  }

  const checkQuery = 'SELECT id FROM likes WHERE user_id = ? AND tweet_id = ?';
  db.query(checkQuery, [userId, tweetid], (err, result) => {
    if (err) {
      console.error('Database error:', err);
      return res.status(500).json({ message: 'Database error' });
    }

    if (result.length > 0) {
      // Unlike the tweet
      const deleteQuery = 'DELETE FROM likes WHERE user_id = ? AND tweet_id = ?';
      db.query(deleteQuery, [userId, tweetid], (err) => {
        if (err) {
          console.error('Database error:', err);
          return res.status(500).json({ message: 'Database error' });
        }
        // Remove notification
        const deleteNotificationQuery = 'DELETE FROM notifications WHERE user_id = ? AND related_post_id = ? AND notification_type = "like"';
        db.query(deleteNotificationQuery, [userId, tweetid], (err) => {
          if (err) console.error('Error deleting notification:', err);
        });
        return res.json({ liked: false, message: 'Tweet unliked' });
      });
    } else {
      // Like the tweet
      const insertQuery = 'INSERT INTO likes (user_id, tweet_id) VALUES (?, ?)';
      db.query(insertQuery, [userId, tweetid], (err) => {
        if (err) {
          console.error('Database error:', err);
          return res.status(500).json({ message: 'Database error' });
        }

        // Insert notification
        const notificationMessage = `${req.user.username} liked your post`;
        const insertNotificationQuery = 'INSERT INTO notifications (user_id, notification_type, related_post_id, message) VALUES (?, "like", ?, ?)';
        db.query(insertNotificationQuery, [req.user.userId, tweetid, notificationMessage], (err) => {
          if (err) {
            console.error('Error inserting notification:', err);
            return res.status(500).json({ message: 'Error inserting notification' });
          }
          return res.json({ liked: true, message: 'Tweet liked' });
        });
      });
    }
  });
});
app.get('/api/notifications/:userId', (req, res) => {
  const userId = req.params.userId;

  const query = 'SELECT * FROM notifications WHERE user_id = ? AND is_read = false ORDER BY created_at DESC';
  db.query(query, [userId], (err, result) => {
    if (err) {
      console.error("Error fetching notifications:", err);
      return res.status(500).json({ message: 'Error fetching notifications' });
    }

    res.json(result);
  });
});


app.get('/api/tweets/:tweetId/comments/count', (req, res) => {
    const { tweetId } = req.params;

    db.query('SELECT COUNT(*) AS count FROM comments WHERE tweet_id = ?', [tweetId], (error, results) => {
        if (error) {
            console.error('Error fetching comment count:', error);
            return res.status(500).json({ error: 'Internal Server Error' });
        }

        res.json({ count: results[0].count }); // Send { count: X }
    });
});
app.post('/api/notifications/:notificationId/read', (req, res) => {
  const notificationId = req.params.notificationId;

  const query = 'UPDATE notifications SET is_read = true WHERE id = ?';
  db.query(query, [notificationId], (err, result) => {
    if (err) {
      console.error("Error updating notification:", err);
      return res.status(500).json({ message: 'Error marking notification as read' });
    }

    res.json({ message: 'Notification marked as read' });
  });
});


app.listen(PORT, () => {
  console.log(`Server is running on port ${PORT}`);
});
