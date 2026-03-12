import admin from 'firebase-admin';
import serviceAccount from './gateman-fef40-firebase-adminsdk-fbsvc-412c3cfd54.json' with { type: 'json' };

try {
  if (!admin.apps.length) {
    admin.initializeApp({
      credential: admin.credential.cert(serviceAccount)
    });
  }
  
  console.log('✅ Firebase Admin SDK initialized successfully');
  console.log(`🚀 Connected to project: ${admin.app().options.credential.projectId}`);
  
} catch (error) {
  console.error('❌ Firebase Admin initialization failed:', error.message);
}

export default admin;