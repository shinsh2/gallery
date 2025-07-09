pipeline {
	environment {
		APPLICATION ='gallery'
		NCP_REGISTRY = 'ncp-cr.kr.ncr.ntruss.com'
		NCP_REPOSITORY = 'gallery'
	}
	agent any
	stages{
		// 댓글을 남길 Jira 티켓을 검색한다. 해당 과정은 STG만 수행한다.
		// stage('Jira Ticket Search'){
		// 	steps {
		// 	  script{
		// 	   echo "Jira Ticket Search"
		// 	   searchIssue = jiraJqlSearch jql: 'project = '+"PBLPZRO001"+' and status not in ("Closed","Done","Drop","개발 배포 완료","일반 배포 완료","긴급 릴리즈 완료",등록) and issuetype = "릴리즈" and summary ~ "' + Application + '" ORDER BY updated DESC', maxResults: 1, site: 'prdJira'
		// 	   JIRA_TICKET = searchIssue.data.issues[0].key
		// 	  }
		//  	}
		// }
		stage('Build') {
			steps {
				script {
					echo "빌드 수행"
                    sh "cd frontend; npm install; npm run build"
                    // sh "cd front-end; npm install && npm run build --mode=development"
                    sh "mvn -U clean package -DskipTests=true -f pom.xml"
				}
			}
		}
		// 소나큐브 검사를 수행한다. 해당 과정은 STG의 경우 Fail시 빌드가 중단된다.
		// stage('SonarQube 검사') {
		// 	steps {
		// 		script {
        //             echo "코드품질검사 수행"

        //        		withSonarQubeEnv('KB SonarQube') {
		// 				sh "/fsutil/sonar-scanner-4.5.0.2216-linux/bin/sonar-scanner -Dsonar.projectKey=" + Application + " -Dsonar.projectBaseDir="+ WORKSPACE + " -Dsonar.sources=src -Dsonar.java.binaries=target/classes -Dsonar.mybatis.dbvendor=db2"
		// 			}
		// 			timeout(time:2, unit: 'MINUTES') {
		// 				qualitygate = waitForQualityGate()
		// 		        if (qualitygate.status != 'OK') {
		// 				  	jiraAddComment comment: Application + ' SonarQube 품질검사 : FAIL \n 결과확인 URL: http://sonarqube.kbstar.com:9000', idOrKey: JIRA_TICKET, site: 'prdJira'
		// 				    error "Pipeline abored due to quality gate failure: ${qualitygate.status}"
		// 			    }
		// 			    else{
		// 			       	jiraAddComment comment: Application + ' SonarQube 품질검사 : OK \n 결과확인 URL: http://sonarqube.kbstar.com:9000', idOrKey: JIRA_TICKET, site: 'prdJira'
		// 			    }
		// 		    }
		// 		}
		// 	}
		// }
		// 스패로우 검사를 수행한다. 해당 과정은 STG의 경우 Fail시 빌드가 중단된다.
 		// stage ('Sparrow 보안 취약성 검사') {
		// 	steps {
		// 		script{
		// 			echo "보안 취약성 검사 수행"
					
		// 			runSparrow = sh(script:'/fsapp/sparrow5_client/sparrow-client.sh -P liivreboot-adm -U 0346 -PW liiv1234 -S http://172.17.26.225:28080 -SD ' + WORKSPACE, returnStdout: true)
		// 			def rstCount = sh(script:"echo \"${runSparrow}\" | awk -F\'\n\' \'{if(\$1~/Total defects/) print}\' | awk -F\' \' \'{print \$NF}\'", returnStdout: true).trim()
			
		// 			echo rstCount
		// 			if (rstCount == '0') {
		// 				jiraAddComment comment: Application + ' Sparrow 취약성 검사: OK \n 결과확인 URL:http://172.17.26.225:28080', idOrKey: JIRA_TICKET, site: 'prdJira'

		// 			}else{
		// 				jiraAddComment comment: Application + ' Sparrow 취약성 검사: FAIL \n 결과확인 URL:http://172.17.26.225:28080', idOrKey: JIRA_TICKET, site: 'prdJira'
		// 				build.doStop()
		// 			}	
		// 		}
		// 	}
		// }
		// 도커 빌드를 수행하여 NCR에 파일을 업로드한다.
		stage('docker build') {
			steps {
				script {
					echo "도커 빌드 수행"
                   	sh "docker build -t " + NCP_REGISTRY + "/" + APPLICATION + ":$BUILD_NUMBER ."
                   	sh "docker images"
					def NCP_CR_USERNAME
					def NCP_CR_PASSWORD
					withCredentials([usernamePassword(credentialsId: 'NCP_IAM_CREDENTIAL', passwordVariable: 'PASSWORD', usernameVariable: 'USERNAME')]) {
                    	// echo "$username"
						NCP_CR_USERNAME = USERNAME
						NCP_CR_PASSWORD = PASSWORD
                	}
                   	// echo "$NCP_CR_USERNAME"
					wrap([$class: "MaskPasswordsBuildWrapper", varPasswordPairs: [[password: NCP_CR_USERNAME], [password: NCP_CR_PASSWORD]]]) {
    	                sh "docker login " + NCP_REGISTRY + " -u " + NCP_CR_USERNAME +" -p " + NCP_CR_PASSWORD
					}
					sh "docker push " + NCP_REGISTRY + "/" + APPLICATION + ":$BUILD_NUMBER"	
				}
			}
            post {
		        success {
		            echo 'success'
					sh "docker rmi " + NCP_REGISTRY + "/" + APPLICATION + ":$BUILD_NUMBER"
		        }
		        failure {
		            echo "Pipeline failed"
					sh "docker rmi " + NCP_REGISTRY + "/" + APPLICATION + ":$BUILD_NUMBER"
		        }
			}	
		}
		stage('k8s deploy') {
			steps {
				script {
					sh "export PATH=$PATH:$HOME/ncp-iam-authenticator; helm upgrade --install " + APPLICATION + " ./helmchart --debug --set image.tag=$BUILD_NUMBER"
                    sh "export PATH=$PATH:$HOME/ncp-iam-authenticator; helm status " + APPLICATION
                    sh "export PATH=$PATH:$HOME/ncp-iam-authenticator; kubectl get pod,svc -o wide"
				}
			}
        }
	}
}
