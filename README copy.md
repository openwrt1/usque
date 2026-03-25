下面是爪云的脚本


apiVersion: app.sealos.io/v1
kind: Template
metadata:
  name: quic-test
spec:
  title: "QUIC UDP Echo Test"
  description: "Test UDP/QUIC datagram forwarding"
  templateType: inline
  categories:
    - tool
  defaults:
    app_name:
      type: string
      value: quic-test-${{ random(8) }}
---
apiVersion: v1
kind: Service
metadata:
  name: ${{ defaults.app_name }}
  labels:
    cloud.sealos.io/app-deploy-manager: ${{ defaults.app_name }}
spec:
  type: NodePort
  ports:
    - name: udp-echo
      port: 23112
      targetPort: 23112
      protocol: UDP
  selector:
    app: ${{ defaults.app_name }}
---
apiVersion: apps/v1
kind: Deployment
metadata:
  name: ${{ defaults.app_name }}
  annotations:
    originImageName: ghcr.io/openwrt1/quic-test:main
    deploy.cloud.sealos.io/minReplicas: "1"
    deploy.cloud.sealos.io/maxReplicas: "1"
  labels:
    cloud.sealos.io/app-deploy-manager: ${{ defaults.app_name }}
    app: ${{ defaults.app_name }}
spec:
  replicas: 1
  revisionHistoryLimit: 1
  selector:
    matchLabels:
      app: ${{ defaults.app_name }}
  template:
    metadata:
      labels:
        app: ${{ defaults.app_name }}
    spec:
      containers:
        - name: ${{ defaults.app_name }}
          image: ghcr.io/openwrt1/quic-test:main
          imagePullPolicy: Always
          ports:
            - name: udp-echo
              containerPort: 23112
              protocol: UDP
          resources:
            requests:
              cpu: 10m
              memory: 32Mi
            limits:
              cpu: 200m
              memory: 128Mi
